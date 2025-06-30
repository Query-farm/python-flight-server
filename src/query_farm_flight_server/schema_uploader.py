import hashlib
from dataclasses import dataclass

import msgpack
import zstandard as zstd
from mypy_boto3_s3 import S3Client

from query_farm_flight_server.util import hex_to_url_safe_characters

CACHE_CONTROL = "max-age=31536000"


@dataclass
class UploadResult:
    sha256_hash: str
    s3_path: str
    compressed_data: bytes | None


def _compress_and_prefix_with_length(data: bytes, compression_level: int) -> bytes:
    compressor = zstd.ZstdCompressor(level=compression_level)
    compressed_data = compressor.compress(data)
    result = msgpack.packb([len(data), compressed_data])
    assert result
    return result


def _hash_value(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _build_sha256_key_name_and_hash(key_prefix: str, data: bytes) -> tuple[str, str]:
    sha256_hash = _hash_value(data)
    return (
        f"{key_prefix}/{hex_to_url_safe_characters(sha256_hash)}",
        sha256_hash,
    )


def upload(
    *,
    compression_level: int | None,
    s3_client: S3Client | None,
    data: bytes,
    key_prefix: str,
    bucket: str,
    skip_upload: bool,
) -> UploadResult:
    """
    Upload data to S3 bucket.

    Args:
        compression_level (int | None): Level of compression to apply to data.
        s3_client (Any): S3 client object.
        data (bytes): Data to upload.
        key_prefix (str): Prefix for the S3 key.
        bucket (str): S3 bucket name.
        skip_upload (bool): Flag to skip the actual upload.

    Returns:
        UploadResult: Object containing sha256 hash, S3 path, and compressed data.
    """
    if compression_level is not None:
        data = _compress_and_prefix_with_length(data, compression_level)

    s3_path, sha256_hash = _build_sha256_key_name_and_hash(key_prefix, data)

    if not skip_upload:
        assert s3_client, "S3 client must be provided if not skipping upload"
        s3_client.put_object(
            Body=data,
            Bucket=bucket,
            Key=s3_path,
            ACL="public-read",
            CacheControl=CACHE_CONTROL,
        )

    return UploadResult(sha256_hash=sha256_hash, s3_path=s3_path, compressed_data=data)
