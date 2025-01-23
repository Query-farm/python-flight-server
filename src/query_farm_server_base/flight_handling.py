import io
import json
import struct
from dataclasses import dataclass
from typing import Any, Callable, TypeVar

import duckdb
import immutables
import msgpack
import pyarrow.flight as flight
import sqlglot
import structlog
import zstandard as zstd
from duckdb_query_tools import duckdb_serialized_expression, sql_statement_analyzer
from pydantic import BaseModel

ticket_with_metadata_indicator = b"<TICKET_WITH_METADATA>"


class FlightTicketData(BaseModel):
    flight_name: str


T = TypeVar("T", bound=FlightTicketData)


def endpoint(*, ticket_data: T, allow_metadata: bool) -> flight.FlightEndpoint:
    """Create a FlightEndpoint that allows metadata filtering to be passed
    back to the same server location"""
    packed_data = msgpack.packb(ticket_data)

    return flight.FlightEndpoint(
        f"<TICKET_ALLOWS_METADATA>{packed_data}" if allow_metadata else packed_data,
        [
            # This is the location.
            "arrow-flight-reuse-connection://?"
        ],
    )


def decode_ticket(*, ticket: flight.Ticket, model_selector: Callable[[str], type[T]]) -> tuple[T, dict[str, str]]:
    """
    Decode a ticket that has embedded and compressed metadata.

    There is no concept of multiple headers handled here, headers are strings.
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

        # The ticket itself is a msgpack message.
        msgpack_ticket_contents = stream.read(ticket_data_length)

        basic_data = FlightTicketData.model_validate(msgpack_ticket_contents)

        decoded_ticket_data = model_selector(basic_data.flight_name).model_validate(
            msgpack.unpackb(msgpack_ticket_contents, raw=False)
        )

        metadata_decompressed_length = struct.unpack("<I", stream.read(4))[0]
        if metadata_decompressed_length > 1024 * 1024 * 2:
            raise flight.FlightUnavailableError("Decompressed Flight metadata is too large limit is 2mb.")

        metadata = stream.read()
        parsed_headers: dict[str, str] = {}
        try:
            # That metadata is zstd compressed, so we need to decompress it.
            decompressor = zstd.ZstdDecompressor()
            decompressed_metadata = decompressor.decompress(metadata)
            for key, value in json.loads(decompressed_metadata).items():
                if key != "authorization":
                    parsed_headers[key] = value
        except Exception as e:
            raise flight.FlightUnavailableError("Unable to decompress metadata.") from e
        return decoded_ticket_data, parsed_headers
    else:
        decoded_ticket_data = msgpack.unpackb(ticket.ticket)
        return decoded_ticket_data, {}


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


def handle_filter_data(
    *, client_headers: dict[str, list[str]], encoded_metadata: dict[str, str]
) -> dict[str, Any] | None:
    filter_data = None
    for key, value in encoded_metadata.items():
        if key == "airport-duckdb-json-filters":
            filter_data = json.loads(value)
        else:
            # The encoded metadata could want to populate more than just the
            # json filters header, but since client headers are multi-valued deal
            # with this.
            client_headers[key] = [value]

    if filter_data is None:
        filters_as_json = client_headers.get("airport-duckdb-json-filters", [])
        if len(filters_as_json) > 1:
            raise flight.FlightServerError(
                "Only one filter is supported at this time, combine them into a single value."
            )
        elif len(filters_as_json) == 0:
            filter_data = {}
        else:
            filter_data = json.loads(filters_as_json[0])

    return filter_data


def determine_unique_api_call_parameters(
    *,
    parsed_filter_info: ParsedFilterInfo,
    column_names_that_cannot_be_null: list[str],
    addititional_parameter_generator_clauses: list[str],
    parameter_generator_parameters: list[Any],
) -> list[dict[str, Any]]:
    # So before we can do determine the calls, we need to determine the distinct values
    # of each input parameters.

    parameter_generator_clauses: list[str] = []

    if parsed_filter_info.filter_sql_where_clause is not None and parsed_filter_info.filter_sql_where_clause != "":
        parameter_generator_clauses.append(parsed_filter_info.filter_sql_where_clause)

    with duckdb.connect(":memory:") as connection:
        parameter_field_names = []
        for parameter_name, parameter_values in parsed_filter_info.parsed_parameter_values.items():
            create_table_sql = f"CREATE TABLE parameter_{parameter_name} ({parameter_name} {parsed_filter_info.filter_types_as_sql[parameter_name]})"
            connection.execute(create_table_sql)
            parameter_field_names.append(parameter_name)
            connection.executemany(
                f"INSERT INTO parameter_{parameter_name} VALUES (?)",
                [[i if not isinstance(i, immutables.Map) else {**i}] for i in parameter_values],
            )

            # Append the null value.
            if parameter_name not in column_names_that_cannot_be_null:
                connection.execute(f"INSERT INTO parameter_{parameter_name} VALUES (?)", [None])
        joined_parameter_names = ",".join(parsed_filter_info.parsed_parameter_values)
        joined_parameter_table_names = ",".join(map(lambda v: f"parameter_{v}", parameter_field_names))

        parameter_generator_sql = f"select {joined_parameter_names} from {joined_parameter_table_names}"

        parameter_generator_clauses.extend(addititional_parameter_generator_clauses)

        if len(parameter_generator_clauses) > 0:
            parameter_generator_sql += f" where {' and '.join(parameter_generator_clauses)}"

        log.info("Parameter handling", parameter_generator_sql=parameter_generator_sql)
        api_call_parameter_rows = connection.execute(parameter_generator_sql, parameter_generator_parameters).arrow()

    return api_call_parameter_rows.to_pylist()
    # Now that we have all of the parameter tables, lets get the actual values that can be specified.
