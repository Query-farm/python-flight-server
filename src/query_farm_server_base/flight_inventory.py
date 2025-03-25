from dataclasses import dataclass
from typing import Any, Literal

import boto3
import msgpack
import pyarrow as pa
import pyarrow.flight as flight
import structlog
import zstandard as zstd

from . import schema_uploader

log = structlog.get_logger()

SCHEMA_BASE_URL = "https://schemas.beta.database.flights"
SCHEMA_BUCKET_NAME = "schemas.beta.database.flights"

# This is the level of ZStandard compression to use for individual FlightInfo
# objects, since the schemas are pretty small, we can use a lower compression
# preferring fast decompression.
SCHEMA_COMPRESSION_LEVEL = 3

# This is the level of ZStandard compression to use for the top-level schema
# JSON information.
SCHEMA_TOP_LEVEL_COMPRESSION_LEVEL = 12

STANDARD_WRITE_OPTIONS = pa.ipc.IpcWriteOptions(
    compression=pa.Codec("zstd", 3),
)


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
    ):
        self.type = type
        self.catalog = catalog
        self.schema = schema
        self.name = name
        self.comment = comment
        self.input_schema = input_schema
        self.action_name = action_name

    def serialize(self) -> bytes:
        values_to_pack = {
            "type": self.type,
            "catalog": self.catalog,
            "schema": self.schema,
            "name": self.name,
            "comment": self.comment,
            "action_name": self.action_name,
        }
        if self.input_schema:
            values_to_pack["input_schema"] = self.input_schema.serialize().to_pybytes()

        return msgpack.packb(values_to_pack)


FlightInventoryWithMetadata = tuple[flight.FlightInfo, FlightSchemaMetadata]


def upload_and_generate_schema_list(
    *,
    flight_service_name: str,
    flight_inventory: dict[str, dict[str, list[FlightInventoryWithMetadata]]],
    schema_details: dict[str, SchemaInfo],
    skip_upload: bool,
    catalog_version: int,
    catalog_version_fixed: bool,
    enable_sha256_caching: bool = True,
    serialize_inline: bool = False,
) -> bytes:
    serialized_schema_data: list[dict[str, Any]] = []
    s3_client = boto3.client("s3")
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
    for catalog_name, schema_names in flight_inventory.items():
        for schema_name, schema_items in schema_names.items():
            # Serialize all of the FlightInfo into an array.
            packed_flight_info = msgpack.packb(
                [flight_info.serialize() for flight_info, _metadata in schema_items]
            )

            log.info(f"Uploading schema for {schema_name}", skip_upload=skip_upload)
            uploaded_schema_contents = schema_uploader.upload(
                s3_client=s3_client,
                data=packed_flight_info,
                compression_level=SCHEMA_COMPRESSION_LEVEL,
                key_prefix=f"schemas/{flight_service_name}/{catalog_name}",
                bucket=SCHEMA_BUCKET_NAME,
                skip_upload=skip_upload or serialize_inline,
            )

            schema_path = f"{SCHEMA_BASE_URL}/{uploaded_schema_contents.s3_path}"

            assert uploaded_schema_contents.compressed_data

            all_schema_flights_serialized.append(
                [
                    uploaded_schema_contents.sha256_hash,
                    uploaded_schema_contents.compressed_data,
                ]
            )

            serialized_schema_data.append(
                {
                    "schema": schema_name,
                    "description": schema_details[schema_name].description
                    if schema_name in schema_details
                    else "",
                    "contents": {
                        "url": schema_path if not serialize_inline else None,
                        "sha256": uploaded_schema_contents.sha256_hash,
                    },
                    "tags": schema_details[schema_name].tags
                    if schema_name in schema_details
                    else {},
                }
            )

    all_packed = msgpack.packb(all_schema_flights_serialized)
    all_schema_contents_upload = schema_uploader.upload(
        s3_client=s3_client,
        data=all_packed,
        key_prefix=f"schemas/{flight_service_name}",
        bucket=SCHEMA_BUCKET_NAME,
        compression_level=None,  # Don't compress since all contained schemas are compressed
        skip_upload=skip_upload or serialize_inline,
    )
    all_schema_path = f"{SCHEMA_BASE_URL}/{all_schema_contents_upload.s3_path}"

    schemas_list_data = {
        "schemas": serialized_schema_data,
        # This encodes the contents of all schemas in one file.
        "contents": {
            "sha256": all_schema_contents_upload.sha256_hash,
            "url": all_schema_path if not serialize_inline else None,
            "serialized": all_schema_contents_upload.compressed_data if serialize_inline else None,
        },
        "version_info": [catalog_version, catalog_version_fixed],
    }

    packed_data = msgpack.packb(schemas_list_data)
    compressor = zstd.ZstdCompressor(level=SCHEMA_TOP_LEVEL_COMPRESSION_LEVEL)
    compressed_data = compressor.compress(packed_data)
    return msgpack.packb([len(packed_data), compressed_data])
