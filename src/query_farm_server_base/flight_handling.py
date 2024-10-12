import io
import json
import struct

import pyarrow.flight as flight

import zstandard as zstd

ticket_with_metadata_indicator = b"<TICKET_WITH_METADATA>"


def decode_ticket_with_metadata(ticket: flight.Ticket) -> tuple[str, dict[str, list[str]]]:
    """
    Decode a ticket that has embedded and compressed metadata.
    """
    if (
        ticket.ticket[0 : min(len(ticket_with_metadata_indicator), len(ticket.ticket))]
        == ticket_with_metadata_indicator
    ):
        # We have a ticket with metadata.
        stream = io.BytesIO(ticket.ticket)
        stream.seek(len(ticket_with_metadata_indicator))
        # Unpack the byte string as a uint32 ('I' is the format code for uint32)
        ticket_data_length = struct.unpack("<I", stream.read(4))[0]
        decoded_ticket = stream.read(ticket_data_length).decode("utf-8")

        metadata_decompressed_length = struct.unpack("<I", stream.read(4))[0]
        if metadata_decompressed_length > 1024 * 1024 * 2:
            raise flight.FlightUnavailableError("Decompressed Flight metadata is too large limit is 2mb.")

        metadata = stream.read()
        parsed_headers: dict[str, list[str]] = {}
        try:
            # That metadata is zstd compressed, so we need to decompress it.
            decompressor = zstd.ZstdDecompressor()
            decompressed_metadata = decompressor.decompress(metadata)
            for key, value in json.loads(decompressed_metadata).items():
                if key != "authorization":
                    parsed_headers[key] = [value]
        except Exception as e:
            raise flight.FlightUnavailableError("Unable to decompress metadata.") from e
        return decoded_ticket, parsed_headers
    else:
        decoded_ticket = ticket.ticket.decode("utf-8")
        return decoded_ticket, {}
