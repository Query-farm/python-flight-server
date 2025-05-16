from typing import Any, Literal, TypeVar, get_args, get_origin  # noqa: UP035

import msgpack
import pyarrow as pa
import pyarrow.flight as flight
from pydantic import BaseModel, ConfigDict, Field, field_validator


def serialize_record_batch(value: pa.RecordBatch, _info: Any) -> bytes | None:
    if value is None:
        return None
    sink = pa.BufferOutputStream()
    writer = pa.ipc.new_stream(sink, value.schema)
    writer.write_batch(value)
    writer.close()

    return sink.getvalue()


def serialize_flight_descriptor(value: flight.FlightDescriptor, _info: Any) -> bytes:
    return value.serialize()


def deserialize_record_batch(cls: Any, value: Any) -> pa.RecordBatch | None:
    if value is None:
        return None
    if isinstance(value, pa.RecordBatch):
        return value
    try:
        # handle both raw JSON string and parsed dict
        if isinstance(value, bytes):
            buffer = pa.BufferReader(value)
            # Open the IPC stream
            ipc_stream = pa.ipc.open_stream(buffer)

            # Read the RecordBatch
            record_batch = next(ipc_stream)
            return record_batch
        raise NotImplementedError("Unable to deserialize Arrow record batch")
    except Exception as e:
        raise ValueError(f"Invalid Arrow record batch: {e}") from e


def deserialize_record_batch_or_none(cls: Any, value: Any) -> pa.RecordBatch | None:
    if value is None or value == b"":
        return None
    return deserialize_record_batch(cls, value)


def deserialize_schema(cls: Any, value: Any) -> pa.Schema:
    if isinstance(value, pa.Schema):
        return value
    try:
        # handle both raw JSON string and parsed dict
        if isinstance(value, bytes):
            return pa.ipc.read_schema(pa.BufferReader(value))

        return pa.schema(value)
    except Exception as e:
        raise ValueError(f"Invalid Arrow schema: {e}") from e


def deserialize_schema_or_none(cls: Any, value: Any) -> pa.Schema:
    if value is None or value == b"":
        return None
    return deserialize_schema(cls, value)


def deserialize_flight_descriptor(cls: Any, value: Any) -> flight.FlightDescriptor:
    if isinstance(value, flight.FlightDescriptor):
        return value
    try:
        # handle both raw JSON string and parsed dict
        if isinstance(value, bytes):
            return flight.FlightDescriptor.deserialize(value)
    except Exception as e:
        raise ValueError(f"Invalid Flight descriptor: {e}") from e


class CreateTableParameters(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2
    catalog_name: str
    schema_name: str
    table_name: str

    arrow_schema: pa.Schema
    _validate_arrow_schema = field_validator("arrow_schema", mode="before")(deserialize_schema)

    on_conflict: Literal["error", "ignore", "replace"]

    not_null_constraints: list[int]
    unique_constraints: list[int]
    check_constraints: list[str]


T = TypeVar("T", bound=BaseModel)


def unpack_with_model(action: flight.Action, model_cls: type[T]) -> T:
    decode_fields: set[str] = set()
    for name, field in model_cls.model_fields.items():
        if isinstance(field.annotation, str) or (
            get_origin(field.annotation) is list
            and get_args(field.annotation) is str
            or get_origin(field.annotation) is Literal
        ):
            decode_fields.add(name)

    unpacked = msgpack.unpackb(
        action.body.to_pybytes(),
        raw=True,
        object_hook=lambda s: {
            k.decode("utf8"): v.decode("utf8") if k.decode("utf8") in decode_fields else v
            for k, v in s.items()
        },
    )
    return model_cls.model_validate(unpacked)


class DropObjectParameters(BaseModel):
    type: Literal["table", "schema"]
    catalog_name: str
    schema_name: str
    name: str
    ignore_not_found: bool


class AlterBase(BaseModel):
    catalog: str
    schema_name: str = Field("schema_name", alias="schema")
    name: str
    ignore_not_found: bool


class AddColumnParameters(AlterBase):
    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2
    column_schema: pa.Schema
    if_column_not_exists: bool

    _validate_column_schema = field_validator("column_schema", mode="before")(deserialize_schema)


class AddConstraintParameters(AlterBase):
    constraint: str


class AddFieldParameters(AlterBase):
    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2
    column_path: list[str]
    column_schema: pa.Schema
    if_field_not_exists: bool

    _validate_field_schema = field_validator("column_schema", mode="before")(deserialize_schema)


class ChangeColumnTypeParameters(AlterBase):
    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2
    column_schema: pa.Schema
    expression: str

    _validate_column_schema = field_validator("column_schema", mode="before")(deserialize_schema)


class ColumnStatisticsParameters(AlterBase):
    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2
    flight_descriptor: flight.FlightDescriptor
    column_name: str
    type: str

    _validate_flight_descriptor = field_validator("flight_descriptor", mode="before")(
        deserialize_flight_descriptor
    )


class CreateSchemaParameters(BaseModel):
    catalog_name: str
    schema_name: str = Field("schema_name", alias="schema")

    comment: str | None = None
    tags: dict[str, str]


class CreateTransactionParameters(BaseModel):
    catalog_name: str


class DropNotNullParameters(AlterBase):
    column_name: str


class EndpointsParametersParameters(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2

    json_filters: str
    column_ids: list[int]

    table_function_parameters: pa.RecordBatch | None

    _validate_table_function_parameters = field_validator(
        "table_function_parameters", mode="before"
    )(deserialize_record_batch_or_none)


class EndpointsParameters(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2
    descriptor: flight.FlightDescriptor
    _validate_descriptor = field_validator("descriptor", mode="before")(
        deserialize_flight_descriptor
    )
    parameters: EndpointsParametersParameters


class ListSchemasParameters(BaseModel):
    catalog_name: str


class RemoveColumnParameters(AlterBase):
    removed_column: str
    if_column_exists: bool
    cascade: bool


class RemoveFieldParameters(AlterBase):
    column_path: list[str]
    if_column_exists: bool
    cascade: bool


class RenameColumnParameters(AlterBase):
    old_name: str
    new_name: str


class RenameFieldParameters(AlterBase):
    column_path: list[str]
    new_name: str


class RenameTableParameters(AlterBase):
    new_table_name: str


class SetDefaultParameters(AlterBase):
    column_name: str
    expression: str


class SetNotNullParameters(AlterBase):
    column_name: str


class CatalogVersionParameters(BaseModel):
    catalog_name: str


class TableFunctionFlightInfoParameters(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2
    descriptor: flight.FlightDescriptor

    parameters: pa.RecordBatch
    table_input_schema: pa.Schema | None

    _validate_flight_descriptor = field_validator("descriptor", mode="before")(
        deserialize_flight_descriptor
    )

    _validate_parameters = field_validator("parameters", mode="before")(deserialize_record_batch)

    _validate_table_input_schema = field_validator("table_input_schema", mode="before")(
        deserialize_schema_or_none
    )


def table_function_flight_info(action: flight.Action) -> TableFunctionFlightInfoParameters:
    return unpack_with_model(action, TableFunctionFlightInfoParameters)


def catalog_version(action: flight.Action) -> CatalogVersionParameters:
    return unpack_with_model(action, CatalogVersionParameters)


def add_column(action: flight.Action) -> AddColumnParameters:
    return unpack_with_model(action, AddColumnParameters)


def add_constraint(action: flight.Action) -> AddConstraintParameters:
    return unpack_with_model(action, AddConstraintParameters)


def add_field(action: flight.Action) -> AddFieldParameters:
    return unpack_with_model(action, AddFieldParameters)


def change_column_type(action: flight.Action) -> ChangeColumnTypeParameters:
    return unpack_with_model(action, ChangeColumnTypeParameters)


def create_table(action: flight.Action) -> CreateTableParameters:
    return unpack_with_model(action, CreateTableParameters)


def column_statistics(action: flight.Action) -> ColumnStatisticsParameters:
    return unpack_with_model(action, ColumnStatisticsParameters)


def create_schema(action: flight.Action) -> CreateSchemaParameters:
    return unpack_with_model(action, CreateSchemaParameters)


def create_transaction(action: flight.Action) -> CreateTransactionParameters:
    return unpack_with_model(action, CreateTransactionParameters)


def drop_not_null(action: flight.Action) -> DropNotNullParameters:
    return unpack_with_model(action, DropNotNullParameters)


def drop_schema(action: flight.Action) -> DropObjectParameters:
    return unpack_with_model(action, DropObjectParameters)


def drop_table(action: flight.Action) -> DropObjectParameters:
    return unpack_with_model(action, DropObjectParameters)


def endpoints(action: flight.Action) -> EndpointsParameters:
    return unpack_with_model(action, EndpointsParameters)


def list_schemas(action: flight.Action) -> ListSchemasParameters:
    return unpack_with_model(action, ListSchemasParameters)


def remove_column(action: flight.Action) -> RemoveColumnParameters:
    return unpack_with_model(action, RemoveColumnParameters)


def remove_field(action: flight.Action) -> RemoveFieldParameters:
    return unpack_with_model(action, RemoveFieldParameters)


def rename_column(action: flight.Action) -> RenameColumnParameters:
    return unpack_with_model(action, RenameColumnParameters)


def rename_field(action: flight.Action) -> RenameFieldParameters:
    return unpack_with_model(action, RenameFieldParameters)


def rename_table(action: flight.Action) -> RenameTableParameters:
    return unpack_with_model(action, RenameTableParameters)


def set_default(action: flight.Action) -> SetDefaultParameters:
    return unpack_with_model(action, SetDefaultParameters)


def set_not_null(action: flight.Action) -> SetNotNullParameters:
    return unpack_with_model(action, SetNotNullParameters)
