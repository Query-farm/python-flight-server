import base64
import io
from collections.abc import Callable, Generator
from typing import Any, Literal, TypeVar, get_args, get_origin

import msgpack
import pyarrow as pa
import pyarrow.flight as flight
from pydantic import BaseModel


class FlightTicketData(BaseModel):
    flight_name: str
    json_filters: str | None = None
    column_ids: list[int] | None = None

    @staticmethod
    def unpack(src: bytes) -> "FlightTicketData":
        decode_fields = {"flight_name", "json_filters"}
        unpacked = msgpack.unpackb(
            src,
            raw=True,
            object_hook=lambda s: {
                k.decode("utf8"): v.decode("utf8") if k.decode("utf8") in decode_fields else v
                for k, v in s.items()
            },
        )

        return FlightTicketData.model_validate(unpacked)


T = TypeVar("T", bound=FlightTicketData)
AnyModel = TypeVar("AnyModel", bound=BaseModel)


def generate_record_batches_for_used_fields(
    *, reader: Any, used_field_names: set[str], schema: pa.Schema
) -> Generator[pa.RecordBatch, None, None]:
    """
    Only return the data that is requested in the set of fields names
    otherwise return nulls.
    """
    for batch in reader:
        source_arrays = []
        for column in schema:
            if column.name in used_field_names:
                source_arrays.append(batch.column(column.name))
            else:
                source_arrays.append(pa.nulls(batch.num_rows, column.type))
        new_batch = pa.RecordBatch.from_arrays(source_arrays, schema=schema)

        yield new_batch


def endpoint[AnyModel: BaseModel](
    *,
    ticket_data: AnyModel,
    locations: list[str] | None = None,
) -> flight.FlightEndpoint:
    """Create a FlightEndpoint that allows metadata filtering to be passed
    back to the same server location"""
    if locations is None:
        locations = ["arrow-flight-reuse-connection://?"]
    packed_data = msgpack.packb(ticket_data.model_dump())

    return flight.FlightEndpoint(
        packed_data,
        locations,
    )


def serialize_arrow_ipc_table(table: pa.Table) -> bytes:
    sink = io.BytesIO()
    with pa.ipc.new_stream(sink, table.schema) as writer:
        writer.write_table(table)
    return sink.getvalue()


def dict_to_msgpack_data_uri(data: dict[str, Any]) -> str:
    """
    Convert a dictionary to a data URI with MessagePack encoding.
    """
    msgpack_bytes = msgpack.packb(data, use_bin_type=True)
    assert msgpack_bytes

    # Encode as base64 for inclusion in the data URI
    b64_encoded = base64.b64encode(msgpack_bytes).decode("ascii")

    # Construct the data URI
    return f"data:application/msgpack;base64,{b64_encoded}"


def dict_to_msgpack_duckdb_call_data_uri(data: dict[str, Any]) -> str:
    """
    Convert a dictionary to a data URI with MessagePack encoding for
    duckdb function calls.
    """
    msgpack_bytes = msgpack.packb(data, use_bin_type=True)
    assert msgpack_bytes

    # Encode as base64 for inclusion in the data URI
    b64_encoded = base64.b64encode(msgpack_bytes).decode("ascii")

    # Construct the data URI
    return f"data:application/x-msgpack-duckdb-function-call;base64,{b64_encoded}"


def decode_ticket_model[AnyModel: BaseModel](
    source: flight.Ticket, model_cls: type[AnyModel]
) -> AnyModel:
    decode_fields: set[str] = set()
    for name, field in model_cls.model_fields.items():
        if isinstance(field.annotation, str) or (
            get_origin(field.annotation) is list
            and get_args(field.annotation) is str
            or get_origin(field.annotation) is Literal
        ):
            decode_fields.add(name)

    unpacked = msgpack.unpackb(
        source.ticket,
        raw=True,
        object_hook=lambda s: {
            k.decode("utf8"): v.decode("utf8") if k.decode("utf8") in decode_fields else v
            for k, v in s.items()
        },
    )
    return model_cls.model_validate(unpacked)


def decode_ticket[T: FlightTicketData](
    *,
    ticket: flight.Ticket,
    model_selector: Callable[[str, bytes], T],
) -> tuple[T, dict[str, str]]:
    """
    Decode a ticket that has embedded and compressed metadata.

    There is no concept of multiple headers handled here, headers are strings.
    """
    parsed_headers: dict[str, str] = {}

    basic_data = FlightTicketData.unpack(ticket.ticket)

    if basic_data.json_filters and basic_data.json_filters != "":
        parsed_headers = {"airport-duckdb-json-filters": basic_data.json_filters}

    if basic_data.column_ids and len(basic_data.column_ids) > 0:
        parsed_headers["airport-duckdb-column-ids"] = ",".join(map(str, basic_data.column_ids))

    decoded_ticket_data = model_selector(basic_data.flight_name, ticket.ticket)
    return decoded_ticket_data, parsed_headers
