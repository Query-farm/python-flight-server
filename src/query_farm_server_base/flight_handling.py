import io
import json
import struct
from typing import Any, TypedDict

import pyarrow.flight as flight
import sqlglot
import structlog
import zstandard as zstd
from duckdb_query_tools import duckdb_serialized_expression, sql_statement_analyzer
from dataclasses import dataclass

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


@dataclass
class ParsedFilterInfo:
    parsed_parameter_values: dict[str, list[Any]]
    filter_sql_where_clause: str | None
    filter_types_as_sql: dict[str, str]


log = structlog.get_logger()


def parse_filter_info(
    *, filter_data: Any, input_field_names: list[str], fields_where_values_are_known: set[str]
) -> ParsedFilterInfo:
    filter_sql_where_clause: str | None = None

    if all(key in filter_data for key in ("filters", "column_binding_names_by_index")):
        filter_sql_where_clause, filter_sql_field_type_info = duckdb_serialized_expression.convert_to_sql(
            source=filter_data["filters"],
            bound_column_names=filter_data["column_binding_names_by_index"],
        )

    # There may be additional columns specified in the filter, but not actually necessary to apply to the API call
    # so those should be removed.
    if filter_sql_where_clause == "" or filter_sql_where_clause is None:
        parsed_parameter_values = {}
        filter_types_as_sql = {}
    else:
        ft = sql_statement_analyzer._filter_column_references_statement(
            f"select * from data where {filter_sql_where_clause}", input_field_names
        )

        filter_where_clause = ft.find(sqlglot.exp.Where)
        if filter_where_clause is not None:
            filter_sql_where_clause = filter_where_clause.sql(dialect="duckdb")[len("WHERE ") :]
        else:
            filter_sql_where_clause = None

        log.debug("Filtered where clause", filter_sql=filter_sql_where_clause)
        # Now that we have the filter sql, extract all of the values for the input parameters
        # of this boto3 call.

        parsed_parameter_values = sql_statement_analyzer.determine_input_column_values(
            f"select * from data where {filter_sql_where_clause}",
            input_field_names,
            fields_where_values_are_known,
        )

        log.debug("Parsed parameters", values=parsed_parameter_values)

        filter_types_as_sql = duckdb_serialized_expression.convert_type_to_sql(filter_sql_field_type_info)

    return ParsedFilterInfo(
        parsed_parameter_values=parsed_parameter_values,
        filter_sql_where_clause=filter_sql_where_clause,
        filter_types_as_sql=filter_types_as_sql,
    )
