import json
import struct
from dataclasses import dataclass
from typing import Any

import boto3
import pyarrow as pa
import pyarrow.flight as flight
import structlog
import msgpack
import zstandard as zstd

from . import schema_uploader

FlightInventoryWithMetadata = tuple[flight.FlightInfo, dict[str, Any]]

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


def upload_and_generate_schema_list(
    *,
    flight_service_name: str,
    flight_inventory: dict[str, dict[str, list[FlightInventoryWithMetadata]]],
    schema_details: dict[str, SchemaInfo],
    skip_upload: bool,
) -> list[bytes]:
    serialized_schema_data: list[dict[str, Any]] = []
    s3_client = boto3.client("s3")
    all_schema_flights_with_length_serialized = b""

    for catalog_name, schema_names in flight_inventory.items():
        for schema_name, schema_items in schema_names.items():
            # Accumulate all of the serialized flight info(s) into a buffer where the length
            # of the serialized flight info is stored in a 64-bit integer followed by the serialized
            # flight info.
            packed_flight_info = b""
            for flight_info, _metadata in schema_items:
                serialized_flight_info = flight_info.serialize()
                packed_flight_info += (
                    struct.pack("<I", len(serialized_flight_info))
                    + serialized_flight_info
                )

            # Compress everything with zstd, store the uncompressed length in a 64-bit integer
            # followed by the compressed data.
            log.info(f"Uploading schema for {schema_name}", skip_upload=skip_upload)
            uploaded_schema_contents = schema_uploader.upload(
                s3_client=s3_client,
                data=packed_flight_info,
                compression_level=SCHEMA_COMPRESSION_LEVEL,
                key_prefix=f"schemas/{flight_service_name}/{catalog_name}",
                bucket=SCHEMA_BUCKET_NAME,
                skip_upload=skip_upload,
            )

            schema_path = f"{SCHEMA_BASE_URL}/{uploaded_schema_contents.s3_path}"

            assert uploaded_schema_contents.compressed_data

            all_schema_flights_with_length_serialized += (
                struct.pack("<I", len(uploaded_schema_contents.sha256_hash))
                + uploaded_schema_contents.sha256_hash.encode("utf8")
                + struct.pack("<I", len(uploaded_schema_contents.compressed_data))
                + uploaded_schema_contents.compressed_data
            )

            serialized_schema_data.append(
                {
                    "schema": schema_name,
                    "description": schema_details[schema_name].description
                    if schema_name in schema_details
                    else "",
                    "contents": {
                        "url": schema_path,
                        "sha256": uploaded_schema_contents.sha256_hash,
                        "serialized": None,
                    },
                    "tags": schema_details[schema_name].tags
                    if schema_name in schema_details
                    else {},
                }
            )

    all_schema_contents_upload = schema_uploader.upload(
        s3_client=s3_client,
        data=all_schema_flights_with_length_serialized,
        key_prefix=f"schemas/{flight_service_name}",
        bucket=SCHEMA_BUCKET_NAME,
        compression_level=None,  # Don't compress since all contained schemas are compressed
        skip_upload=skip_upload,
    )
    all_schema_path = f"{SCHEMA_BASE_URL}/{all_schema_contents_upload.s3_path}"

    schemas_list_data = {
            "schemas": serialized_schema_data,
            # This encodes the contents of all schemas in one file.
            "contents": {
                "url": all_schema_path,
                "sha256": all_schema_contents_upload.sha256_hash,
                "serialized": None,
            },
    }

    packed_data = msgpack.packb(schemas_list_data)
    print(packed_data)

    compressor = zstd.ZstdCompressor(level=SCHEMA_TOP_LEVEL_COMPRESSION_LEVEL)
    compressed_data = compressor.compress(packed_data)
    return [struct.pack("<I", len(packed_data)), compressed_data]
