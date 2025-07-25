from dataclasses import dataclass
from typing import Any, Literal

import msgpack
import pyarrow as pa
import pyarrow.flight as flight
from mypy_boto3_s3 import S3Client

from . import schema_uploader, server
from .server import (
    AirportSerializedCatalogRoot,
    AirportSerializedContentsWithSHA256Hash,
    AirportSerializedSchema,
)

# This is the level of ZStandard compression to use for individual FlightInfo
# objects, since the schemas are pretty small, we can use a lower compression
# preferring fast decompression.
SCHEMA_COMPRESSION_LEVEL = 3

# This is the level of ZStandard compression to use for the top-level schema
# JSON information.
SCHEMA_TOP_LEVEL_COMPRESSION_LEVEL = 12


@dataclass
class SchemaInfo:
    description: str
    tags: dict[str, Any]


class FlightSchemaMetadata:
    def __init__(
        self,
        *,
        type: Literal["scalar_function", "table", "table_function"],
        catalog: str,
        schema: str,
        name: str,
        comment: str | None,
        action_name: str | None = None,
        input_schema: pa.Schema | None = None,
        extra_data: bytes | None = None,
    ):
        self.type = type
        self.catalog = catalog
        self.schema = schema
        self.name = name
        self.comment = comment
        self.input_schema = input_schema
        assert action_name is None or action_name != ""
        self.action_name = action_name
        self.extra_data = extra_data

    def serialize(self) -> bytes:
        values_to_pack = {
            "type": self.type,
            "catalog": self.catalog,
            "schema": self.schema,
            "name": self.name,
            "comment": self.comment,
            "action_name": self.action_name,
            "extra_data": self.extra_data,
        }
        if self.input_schema:
            values_to_pack["input_schema"] = self.input_schema.serialize().to_pybytes()
        packed_values = msgpack.packb(values_to_pack)
        assert packed_values
        return packed_values


FlightInventoryWithMetadata = tuple[flight.FlightInfo, FlightSchemaMetadata]

ScalarFunctionStability = Literal["consistent", "volatile", "consistent_within_query"]


class ScalarFunctionMetadata(FlightSchemaMetadata):
    """
    Metadata for a scalar function.

    """

    def __init__(
        self,
        *,
        catalog: str,
        schema: str,
        name: str,
        comment: str | None,
        action_name: str | None = None,
        input_schema: pa.Schema,
        stability: ScalarFunctionStability = "volatile",
    ):
        extra_data = msgpack.packb({"stability": stability})
        assert extra_data
        super().__init__(
            type="scalar_function",
            catalog=catalog,
            schema=schema,
            name=name,
            comment=comment,
            action_name=action_name,
            input_schema=input_schema,
            extra_data=extra_data,
        )


@dataclass
class UploadParameters:
    s3_client: S3Client | None
    base_url: str
    bucket_name: str
    bucket_prefix: str | None = None


def upload_and_generate_schema_list(
    *,
    flight_service_name: str,
    flight_inventory: dict[str, dict[str, list[FlightInventoryWithMetadata]]],
    schema_details: dict[str, SchemaInfo],
    skip_upload: bool,
    catalog_version: int,
    catalog_version_fixed: bool,
    upload_parameters: UploadParameters,
    # schema_base_url: str,
    # schema_bucket_name: str,
    # s3_client: S3Client,
    # s3_bucket_prefix: str | None = None,
    serialize_inline: bool = False,
) -> AirportSerializedCatalogRoot:
    serialized_schema_data: list[AirportSerializedSchema] = []
    all_schema_flights_serialized: list[Any] = []

    # So the problem can be this, if we're doing an inline serialization of the entire catalog
    # we're going to double compress each schema since its compressed at the bottom level
    # then again at the top level, ideally we'd only compress it once.
    #
    # But this means that we'd have to rely on the client doing proper compression of the data
    # and storing it as the cached representations, with the proper ZStandard level, but should
    # we be storing the compressed representations on the disk?
    #
    # I think we can suffer with this problem for a bit longer.
    #
    if upload_parameters and upload_parameters.bucket_prefix:
        upload_parameters.bucket_prefix = (
            upload_parameters.bucket_prefix.rstrip("/") + "/"
            if upload_parameters.bucket_prefix
            else ""
        )

    for catalog_name, schema_names in flight_inventory.items():
        for schema_name, schema_items in schema_names.items():
            # Serialize all of the FlightInfo into an array.
            packed_flight_info = msgpack.packb(
                [flight_info.serialize() for flight_info, _metadata in schema_items]
            )
            assert packed_flight_info

            uploaded_schema_contents = schema_uploader.upload(
                s3_client=upload_parameters.s3_client,
                data=packed_flight_info,
                compression_level=SCHEMA_COMPRESSION_LEVEL,
                key_prefix=f"{upload_parameters.bucket_prefix}schemas/{flight_service_name}/{catalog_name}",
                bucket=upload_parameters.bucket_name,
                skip_upload=skip_upload or serialize_inline,
            )

            assert uploaded_schema_contents.compressed_data

            all_schema_flights_serialized.append(
                [
                    uploaded_schema_contents.sha256_hash,
                    uploaded_schema_contents.compressed_data,
                ]
            )

            serialized_schema_data.append(
                AirportSerializedSchema(
                    name=schema_name,
                    description=schema_details[schema_name].description
                    if schema_name in schema_details
                    else "",
                    contents=AirportSerializedContentsWithSHA256Hash(
                        url=f"{upload_parameters.base_url}/{uploaded_schema_contents.s3_path}"
                        if not serialize_inline
                        else None,
                        sha256=uploaded_schema_contents.sha256_hash,
                        serialized=None,
                    ),
                    tags=schema_details[schema_name].tags if schema_name in schema_details else {},
                )
            )

    all_packed = msgpack.packb(all_schema_flights_serialized)
    assert all_packed

    all_schema_contents_upload = schema_uploader.upload(
        s3_client=upload_parameters.s3_client,
        data=all_packed,
        key_prefix=f"{upload_parameters.bucket_prefix}schemas/{flight_service_name}",
        bucket=upload_parameters.bucket_name,
        compression_level=None,  # Don't compress since all contained schemas are compressed
        skip_upload=skip_upload or serialize_inline,
    )

    return AirportSerializedCatalogRoot(
        schemas=serialized_schema_data,
        contents=AirportSerializedContentsWithSHA256Hash(
            sha256=all_schema_contents_upload.sha256_hash,
            url=f"{upload_parameters.base_url}/{all_schema_contents_upload.s3_path}"
            if not serialize_inline
            else None,
            serialized=all_schema_contents_upload.compressed_data if serialize_inline else None,
        ),
        version_info=server.GetCatalogVersionResult(
            catalog_version=catalog_version, is_fixed=catalog_version_fixed
        ),
    )
