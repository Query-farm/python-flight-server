from collections.abc import Generator
from typing import Any, Literal, TypeVar, get_args, get_origin  # noqa: UP035

import msgpack
import pyarrow as pa
import pyarrow.flight as flight
from pydantic import BaseModel, ConfigDict, Field, field_validator


class FilterData(BaseModel):
    filters: list[Any]
    column_binding_names_by_index: list[str]


def deserialize_json_filters(cls: Any, value: Any) -> FilterData | None:
    if value is None or value == b"":
        return None
    try:
        # handle both raw JSON string and parsed dict
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            return FilterData.model_validate_json(value)
        return FilterData.model_validate(value)
    except Exception as e:
        raise ValueError(f"Invalid filter data: {e}") from e


def serialize_record_batch(value: pa.RecordBatch, _info: Any) -> bytes | None:
    if value is None:
        return None
    sink = pa.BufferOutputStream()
    writer = pa.ipc.new_stream(sink, value.schema)
    writer.write_batch(value)
    writer.close()

    return sink.getvalue().to_pybytes()


def serialize_schema(value: pa.Schema, _info: Any) -> bytes | None:
    if value is None:
        return None
    return value.serialize().to_pybytes()


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


class CreateTable(BaseModel):
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

    primary_key_columns: list[str]
    unique_columns: list[str]
    multi_key_primary_keys: list[str]
    extra_constraints: list[str]


T = TypeVar("T", bound=BaseModel)


def unpack_bytes_with_model[T: BaseModel](value: bytes, model_cls: type[T]) -> T:
    decode_fields: set[str] = set()
    for name, field in model_cls.model_fields.items():
        if isinstance(field.annotation, str) or (
            get_origin(field.annotation) is list
            and get_args(field.annotation) is str
            or get_origin(field.annotation) is Literal
        ):
            decode_fields.add(name)

    unpacked = msgpack.unpackb(
        value,
        raw=True,
        object_hook=lambda s: {
            k.decode("utf8"): v.decode("utf8") if k.decode("utf8") in decode_fields else v
            for k, v in s.items()
        },
    )
    return model_cls.model_validate(unpacked)


def unpack_with_model[T: BaseModel](action: flight.Action, model_cls: type[T]) -> T:
    return unpack_bytes_with_model(action.body.to_pybytes(), model_cls)


class DropObject(BaseModel):
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


class AddColumn(AlterBase):
    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2
    column_schema: pa.Schema
    if_column_not_exists: bool

    _validate_column_schema = field_validator("column_schema", mode="before")(deserialize_schema)


class AddConstraint(AlterBase):
    constraint: str


class AddField(AlterBase):
    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2
    column_path: list[str]
    column_schema: pa.Schema
    if_field_not_exists: bool

    _validate_field_schema = field_validator("column_schema", mode="before")(deserialize_schema)


class ChangeColumnType(AlterBase):
    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2
    column_schema: pa.Schema
    expression: str

    _validate_column_schema = field_validator("column_schema", mode="before")(deserialize_schema)


class ColumnStatistics(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2
    flight_descriptor: flight.FlightDescriptor
    column_name: str
    type: str

    _validate_flight_descriptor = field_validator("flight_descriptor", mode="before")(
        deserialize_flight_descriptor
    )


class CreateSchema(BaseModel):
    catalog_name: str
    schema_name: str = Field("schema_name", alias="schema")

    comment: str | None = None
    tags: dict[str, str]


class CreateTransaction(BaseModel):
    catalog_name: str


class DropNotNull(AlterBase):
    column_name: str


class TableFunctionParameters(BaseModel):
    """
    Because table functions can be called either via DoGet
    or via DoExchange (in the case of in-out table functions),
    these parameters are used for both cases to make things simpler.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2

    where_clause: str | None = None
    parameters: pa.RecordBatch | None

    at_unit: str | None = None
    at_value: str | None = None

    _validate_parameters = field_validator("parameters", mode="before")(
        deserialize_record_batch_or_none
    )


class EndpointsParameters(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2

    json_filters: FilterData | None = None
    _validate_json_filters = field_validator("json_filters", mode="before")(
        deserialize_json_filters
    )

    column_ids: list[int]

    table_function_parameters: pa.RecordBatch | None
    table_function_input_schema: pa.Schema | None

    at_unit: str | None = None
    at_value: str | None = None

    _validate_table_function_parameters = field_validator(
        "table_function_parameters", mode="before"
    )(deserialize_record_batch_or_none)

    _validate_table_function_input_schema = field_validator(
        "table_function_input_schema", mode="before"
    )(deserialize_schema_or_none)


class Endpoints(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2
    descriptor: flight.FlightDescriptor
    _validate_descriptor = field_validator("descriptor", mode="before")(
        deserialize_flight_descriptor
    )
    parameters: EndpointsParameters


class ListSchemas(BaseModel):
    catalog_name: str


class RemoveColumn(AlterBase):
    removed_column: str
    if_column_exists: bool
    cascade: bool


class RemoveField(AlterBase):
    column_path: list[str]
    if_column_exists: bool
    cascade: bool


class RenameColumn(AlterBase):
    old_name: str
    new_name: str


class RenameField(AlterBase):
    column_path: list[str]
    new_name: str


class RenameTable(AlterBase):
    new_table_name: str


class SetDefault(AlterBase):
    column_name: str
    expression: str


class SetNotNull(AlterBase):
    column_name: str


class CatalogVersion(BaseModel):
    catalog_name: str


class TableFunctionFlightInfo(BaseModel):
    """
    Parameters for a table function flight info request.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2

    # The descriptor of the table function.
    descriptor: flight.FlightDescriptor

    # The parameters passed to the table function.
    parameters: pa.RecordBatch

    # The schema of the table function's input if receiving a table as
    # part of an in-out table returning function.
    table_input_schema: pa.Schema | None

    at_unit: str | None = None
    at_value: str | None = None

    _validate_flight_descriptor = field_validator("descriptor", mode="before")(
        deserialize_flight_descriptor
    )

    _validate_parameters = field_validator("parameters", mode="before")(deserialize_record_batch)

    _validate_table_input_schema = field_validator("table_input_schema", mode="before")(
        deserialize_schema_or_none
    )


class FlightInfo(BaseModel):
    """
    Parameters for a table function flight info request.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)  # for Pydantic v2

    # The descriptor of the table function.
    descriptor: flight.FlightDescriptor

    at_unit: str | None = None
    at_value: str | None = None

    _validate_flight_descriptor = field_validator("descriptor", mode="before")(
        deserialize_flight_descriptor
    )


def flight_info(action: flight.Action) -> FlightInfo:
    return unpack_with_model(action, FlightInfo)


def table_function_flight_info(action: flight.Action) -> TableFunctionFlightInfo:
    return unpack_with_model(action, TableFunctionFlightInfo)


def table_function_parameters(value: bytes) -> TableFunctionParameters:
    return unpack_bytes_with_model(value, TableFunctionParameters)


def catalog_version(action: flight.Action) -> CatalogVersion:
    return unpack_with_model(action, CatalogVersion)


def add_column(action: flight.Action) -> AddColumn:
    return unpack_with_model(action, AddColumn)


def add_constraint(action: flight.Action) -> AddConstraint:
    return unpack_with_model(action, AddConstraint)


def add_field(action: flight.Action) -> AddField:
    return unpack_with_model(action, AddField)


def change_column_type(action: flight.Action) -> ChangeColumnType:
    return unpack_with_model(action, ChangeColumnType)


def create_table(action: flight.Action) -> CreateTable:
    return unpack_with_model(action, CreateTable)


def column_statistics(action: flight.Action) -> ColumnStatistics:
    return unpack_with_model(action, ColumnStatistics)


def create_schema(action: flight.Action) -> CreateSchema:
    return unpack_with_model(action, CreateSchema)


def create_transaction(action: flight.Action) -> CreateTransaction:
    return unpack_with_model(action, CreateTransaction)


def drop_not_null(action: flight.Action) -> DropNotNull:
    return unpack_with_model(action, DropNotNull)


def drop_schema(action: flight.Action) -> DropObject:
    return unpack_with_model(action, DropObject)


def drop_table(action: flight.Action) -> DropObject:
    return unpack_with_model(action, DropObject)


def endpoints(action: flight.Action) -> Endpoints:
    return unpack_with_model(action, Endpoints)


def list_schemas(action: flight.Action) -> ListSchemas:
    return unpack_with_model(action, ListSchemas)


def remove_column(action: flight.Action) -> RemoveColumn:
    return unpack_with_model(action, RemoveColumn)


def remove_field(action: flight.Action) -> RemoveField:
    return unpack_with_model(action, RemoveField)


def rename_column(action: flight.Action) -> RenameColumn:
    return unpack_with_model(action, RenameColumn)


def rename_field(action: flight.Action) -> RenameField:
    return unpack_with_model(action, RenameField)


def rename_table(action: flight.Action) -> RenameTable:
    return unpack_with_model(action, RenameTable)


def set_default(action: flight.Action) -> SetDefault:
    return unpack_with_model(action, SetDefault)


def set_not_null(action: flight.Action) -> SetNotNull:
    return unpack_with_model(action, SetNotNull)


# The output of the table function in-out generator, the boolean indicates if the generator
# has more output from the previous chunk.
TableFunctionInOutGeneratorOutput = tuple[pa.RecordBatch, bool]

TableFunctionInOutGenerator = Generator[
    TableFunctionInOutGeneratorOutput,
    # Sent input values, it could be a new RecordBatch or a boolean indicating if the generator should continue
    # with the previous batch.
    pa.RecordBatch | bool | None,
    list[pa.RecordBatch] | None,  # Final output or None
]
