from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import Enum
from typing import Any, NoReturn, ParamSpec, TypeVar

import msgpack
import pyarrow as pa
import pyarrow.flight as flight
import structlog
import zstandard as zstd
from pydantic import BaseModel

from query_farm_flight_server import parameter_types

from . import auth, middleware

# This is the level of ZStandard compression to use for the top-level schema
# JSON information.
SCHEMA_TOP_LEVEL_COMPRESSION_LEVEL = 12


log = structlog.get_logger()

AccountType = TypeVar("AccountType", bound=auth.Account)
TokenType = TypeVar("TokenType", bound=auth.AccountToken)


def read_recordbatch(source: bytes) -> pa.RecordBatch:
    """
    Read a record batch from a byte string.
    """
    buffer = pa.BufferReader(source)
    ipc_stream = pa.ipc.open_stream(buffer)
    return next(ipc_stream)


@dataclass
class CallContext[AccountType: auth.Account, TokenType: auth.AccountToken]:
    context: flight.ServerCallContext
    caller: middleware.SuppliedCredentials[AccountType, TokenType] | None
    logger: structlog.BoundLogger


class GetCatalogVersionResult(BaseModel):
    catalog_version: int
    is_fixed: bool


class CreateTransactionResult(BaseModel):
    identifier: str | None


class AirportSerializedContentsWithSHA256Hash(BaseModel):
    # This is the sha256 hash of the serialized data
    sha256: str
    # This is the url to the serialized data
    url: str | None
    # This is the serialized data, if we are doing inline serialization
    serialized: bytes | None


class AirportSerializedSchema(BaseModel):
    name: str
    description: str
    tags: dict[str, str]
    contents: AirportSerializedContentsWithSHA256Hash


class AirportSerializedCatalogRoot(BaseModel):
    contents: AirportSerializedContentsWithSHA256Hash
    schemas: list[AirportSerializedSchema]
    version_info: GetCatalogVersionResult


P = ParamSpec("P")
R = TypeVar("R")


class ExchangeOperation(str, Enum):
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    SCALAR_FUNCTION = "scalar_function"
    TABLE_FUNCTION_IN_OUT = "table_function_in_out"


class ActionType(str, Enum):
    """
    These are the DoAction action types that are supported by calling the
    separate action handlers.
    """

    # Schema modification actions
    ADD_COLUMN = "add_column"
    ADD_CONSTRAINT = "add_constraint"
    ADD_FIELD = "add_field"
    CHANGE_COLUMN_TYPE = "change_column_type"
    CREATE_SCHEMA = "create_schema"
    CREATE_TABLE = "create_table"
    DROP_NOT_NULL = "drop_not_null"
    DROP_SCHEMA = "drop_schema"
    DROP_TABLE = "drop_table"
    REMOVE_COLUMN = "remove_column"
    REMOVE_FIELD = "remove_field"
    RENAME_COLUMN = "rename_column"
    RENAME_FIELD = "rename_field"
    RENAME_TABLE = "rename_table"
    SET_DEFAULT = "set_default"
    SET_NOT_NULL = "set_not_null"

    # Query and metadata actions
    CATALOG_VERSION = "catalog_version"
    COLUMN_STATISTICS = "column_statistics"
    CREATE_TRANSACTION = "create_transaction"
    ENDPOINTS = "endpoints"
    LIST_SCHEMAS = "list_schemas"
    TABLE_FUNCTION_FLIGHT_INFO = "table_function_flight_info"
    FLIGHT_INFO = "flight_info"


@dataclass
class ActionHandlerSpec:
    method: Callable[..., Any]
    decoder: Callable[[flight.Action], Any]
    post_transform: Callable[[Any], Any] | None = None
    empty_result: bool = True
    pack_result: bool = True


def compress_list_schemas_result(result: AirportSerializedCatalogRoot) -> list[Any]:
    packed_data = msgpack.packb(result.model_dump())
    assert packed_data
    compressor = zstd.ZstdCompressor(level=SCHEMA_TOP_LEVEL_COMPRESSION_LEVEL)
    compressed_data = compressor.compress(packed_data)
    return [len(packed_data), compressed_data]


def serialize_table(table: pa.Table) -> bytes:
    """
    Serialize a PyArrow table to bytes.
    """
    sink = pa.BufferOutputStream()
    with pa.ipc.new_stream(sink, table.schema) as writer:
        writer.write_table(table)
    return sink.getvalue().to_pybytes()


class BasicFlightServer[AccountType: auth.Account, TokenType: auth.AccountToken](
    flight.FlightServerBase, ABC
):
    def __init__(
        self,
        *,
        location: str | None,
        **kwargs: dict[str, Any],
    ) -> None:
        self._location = location
        self.action_handlers_: dict[str, ActionHandlerSpec] = {
            ActionType.ADD_COLUMN: ActionHandlerSpec(
                self.action_add_column,
                parameter_types.add_column,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.ADD_CONSTRAINT: ActionHandlerSpec(
                self.action_add_constraint,
                parameter_types.add_constraint,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.ADD_FIELD: ActionHandlerSpec(
                self.action_add_field,
                parameter_types.add_field,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.CHANGE_COLUMN_TYPE: ActionHandlerSpec(
                self.action_change_column_type,
                parameter_types.change_column_type,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.CREATE_SCHEMA: ActionHandlerSpec(
                self.action_create_schema,
                parameter_types.create_schema,
                lambda v: v.model_dump(),
                False,
            ),
            ActionType.DROP_NOT_NULL: ActionHandlerSpec(
                self.action_drop_not_null,
                parameter_types.drop_not_null,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.DROP_TABLE: ActionHandlerSpec(
                self.action_drop_table, parameter_types.drop_table
            ),
            ActionType.DROP_SCHEMA: ActionHandlerSpec(
                self.action_drop_schema, parameter_types.drop_schema
            ),
            ActionType.REMOVE_COLUMN: ActionHandlerSpec(
                self.action_remove_column,
                parameter_types.remove_column,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.REMOVE_FIELD: ActionHandlerSpec(
                self.action_remove_field,
                parameter_types.remove_field,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.RENAME_COLUMN: ActionHandlerSpec(
                self.action_rename_column,
                parameter_types.rename_column,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.RENAME_FIELD: ActionHandlerSpec(
                self.action_rename_field,
                parameter_types.rename_field,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.RENAME_TABLE: ActionHandlerSpec(
                self.action_rename_table,
                parameter_types.rename_table,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.SET_DEFAULT: ActionHandlerSpec(
                self.action_set_default,
                parameter_types.set_default,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.SET_NOT_NULL: ActionHandlerSpec(
                self.action_set_not_null,
                parameter_types.set_not_null,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.COLUMN_STATISTICS: ActionHandlerSpec(
                self.action_column_statistics,
                parameter_types.column_statistics,
                serialize_table,
                False,
                False,
            ),
            ActionType.CREATE_TABLE: ActionHandlerSpec(
                self.action_create_table,
                parameter_types.create_table,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.ENDPOINTS: ActionHandlerSpec(
                self.action_endpoints,
                parameter_types.endpoints,
                lambda x: [e.serialize() for e in x],
                False,
            ),
            ActionType.TABLE_FUNCTION_FLIGHT_INFO: ActionHandlerSpec(
                self.action_table_function_flight_info,
                parameter_types.table_function_flight_info,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.FLIGHT_INFO: ActionHandlerSpec(
                self.action_flight_info,
                parameter_types.flight_info,
                lambda x: x.serialize(),
                False,
                False,
            ),
            ActionType.LIST_SCHEMAS: ActionHandlerSpec(
                self.action_list_schemas,
                parameter_types.list_schemas,
                compress_list_schemas_result,
                False,
            ),
            ActionType.CATALOG_VERSION: ActionHandlerSpec(
                self.action_catalog_version,
                parameter_types.catalog_version,
                lambda v: v.model_dump(),
                False,
            ),
            ActionType.CREATE_TRANSACTION: ActionHandlerSpec(
                self.action_create_transaction,
                parameter_types.create_transaction,
                lambda v: v.model_dump(),
                False,
            ),
        }

        super().__init__(location, **kwargs)

    def auth_middleware(
        self, context: flight.ServerCallContext
    ) -> middleware.SaveCredentialsMiddleware[AccountType, TokenType]:
        auth_middleware: middleware.SaveCredentialsMiddleware[auth.Account, auth.AccountToken] = (
            context.get_middleware("auth")
        )
        assert isinstance(auth_middleware, middleware.SaveCredentialsMiddleware)
        return auth_middleware

    def credentials_from_context_(
        self, context: flight.ServerCallContext
    ) -> middleware.SuppliedCredentials[AccountType, TokenType] | None | None:
        auth_middleware = self.auth_middleware(context)
        return auth_middleware.credentials

    def auth_logging_items(
        self,
        context: flight.ServerCallContext,
        credentials: middleware.SuppliedCredentials[AccountType, TokenType] | None,
    ) -> dict[str, Any]:
        """Return the items that will be bound to the logger."""
        return {
            "token": None if credentials is None else credentials.token.token,
            "account": None if credentials is None else credentials.account.account_id,
            "address": context.peer(),
        }

    def impl_list_flights(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        criteria: bytes,
    ) -> Iterator[flight.FlightInfo]:
        raise NotImplementedError("impl_list_flights not implemented")

    def list_flights(
        self, context: flight.ServerCallContext, criteria: bytes
    ) -> Iterator[flight.FlightInfo]:
        caller = self.credentials_from_context_(context)

        logger = log.bind(
            **self.auth_logging_items(context, caller),
            criteria=criteria,
        )

        try:
            logger.info("list_flights", criteria=criteria)

            call_context = CallContext(
                context=context,
                caller=caller,
                logger=logger,
            )

            return self.impl_list_flights(
                context=call_context,
                criteria=criteria,
            )
        except Exception as e:
            logger.exception("list_flights", error=str(e))
            raise

    def impl_get_flight_info(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        descriptor: flight.FlightDescriptor,
    ) -> flight.FlightInfo:
        raise NotImplementedError("impl_get_flight_info not implemented")

    def get_flight_info(
        self,
        context: flight.ServerCallContext,
        descriptor: flight.FlightDescriptor,
    ) -> flight.FlightInfo:
        caller = self.credentials_from_context_(context)

        logger = log.bind(
            **self.auth_logging_items(context, caller),
            descriptor=descriptor,
        )
        try:
            logger.info(
                "get_flight_info",
                descriptor=descriptor,
            )

            call_context = CallContext(
                context=context,
                caller=caller,
                logger=logger,
            )

            return self.impl_get_flight_info(
                context=call_context,
                descriptor=descriptor,
            )
        except Exception as e:
            logger.exception("get_flight_info", error=str(e))
            raise

    def impl_do_action(
        self,
        *,
        action: flight.Action,
        context: CallContext[AccountType, TokenType],
    ) -> Iterator[bytes]:
        raise NotImplementedError("impl_do_action not implemented")

    def _unimplemented_action(self, action_name: ActionType) -> NoReturn:
        raise flight.FlightUnavailableError(f"The {action_name} action is not implemented")

    def action_add_column(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.AddColumn,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.ADD_COLUMN)

    def action_add_constraint(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.AddConstraint,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.ADD_CONSTRAINT)

    def action_add_field(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.AddField,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.ADD_FIELD)

    def action_change_column_type(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.ChangeColumnType,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.CHANGE_COLUMN_TYPE)

    # FIXME: build a type for the column statistics, or switch over
    # to an arrow based return set of values.

    def action_column_statistics(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.ColumnStatistics,
    ) -> pa.Table:
        self._unimplemented_action(ActionType.COLUMN_STATISTICS)

    def action_drop_not_null(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.DropNotNull,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.DROP_NOT_NULL)

    def action_drop_table(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.DropObject,
    ) -> None:
        self._unimplemented_action(ActionType.DROP_TABLE)

    def action_endpoints(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.Endpoints,
    ) -> list[flight.FlightEndpoint]:
        self._unimplemented_action(ActionType.ENDPOINTS)

    def action_list_schemas(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.ListSchemas,
    ) -> AirportSerializedCatalogRoot:
        self._unimplemented_action(ActionType.LIST_SCHEMAS)

    def action_remove_column(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.RemoveColumn,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.REMOVE_COLUMN)

    def action_remove_field(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.RemoveField,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.REMOVE_FIELD)

    def action_rename_column(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.RenameColumn,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.RENAME_COLUMN)

    def action_rename_field(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.RenameField,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.RENAME_FIELD)

    def action_rename_table(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.RenameTable,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.RENAME_TABLE)

    def action_set_default(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.SetDefault,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.SET_DEFAULT)

    def action_set_not_null(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.SetNotNull,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.SET_NOT_NULL)

    def action_table_function_flight_info(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.TableFunctionFlightInfo,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.TABLE_FUNCTION_FLIGHT_INFO)

    def action_flight_info(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.FlightInfo,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.FLIGHT_INFO)

    @abstractmethod
    def action_catalog_version(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.CatalogVersion,
    ) -> GetCatalogVersionResult:
        pass

    @abstractmethod
    def action_create_transaction(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.CreateTransaction,
    ) -> CreateTransactionResult:
        pass

    def action_create_schema(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.CreateSchema,
    ) -> AirportSerializedContentsWithSHA256Hash:
        self._unimplemented_action(ActionType.CREATE_SCHEMA)

    def action_create_table(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.CreateTable,
    ) -> flight.FlightInfo:
        self._unimplemented_action(ActionType.CREATE_TABLE)

    def action_drop_schema(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: parameter_types.DropObject,
    ) -> None:
        self._unimplemented_action(ActionType.DROP_SCHEMA)

    def pack_result(self, value: Any) -> Iterator[bytes]:
        result = msgpack.packb(value)
        assert result
        return iter([result])

    def do_action(
        self, context: flight.ServerCallContext, action: flight.Action
    ) -> Iterator[bytes]:
        caller = self.credentials_from_context_(context)

        logger = log.bind(
            **self.auth_logging_items(context, caller),
            action_type=action.type,
        )

        try:
            call_context = CallContext(
                context=context,
                caller=caller,
                logger=logger,
            )

            if handler := self.action_handlers_.get(action.type):
                parameters = handler.decoder(action)
                logger.debug(action.type, parameters=parameters)

                result = handler.method(context=call_context, parameters=parameters)
                if handler.post_transform:
                    result = handler.post_transform(result)
                if handler.empty_result:
                    return iter([])
                result = self.pack_result(result) if handler.pack_result else iter([result])
                return result
            else:
                logger.debug("action", type=action.type, action=action)
                return self.impl_do_action(
                    context=call_context,
                    action=action,
                )
        except Exception as e:
            logger.exception("do_action", error=str(e))
            raise

    def impl_do_exchange(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        descriptor: flight.FlightDescriptor,
        reader: flight.MetadataRecordBatchReader,
        writer: flight.MetadataRecordBatchWriter,
    ) -> None:
        raise NotImplementedError("impl_do_exchange not implemented")

    def _unimplemented_exchange_operation(self, operation: ExchangeOperation) -> NoReturn:
        raise flight.FlightUnavailableError(f"The {operation} operation is not implemented")

    def exchange_insert(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        descriptor: flight.FlightDescriptor,
        reader: flight.MetadataRecordBatchReader,
        writer: flight.MetadataRecordBatchWriter,
        return_chunks: bool,
    ) -> int:
        self._unimplemented_exchange_operation(ExchangeOperation.INSERT)

    def exchange_delete(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        descriptor: flight.FlightDescriptor,
        reader: flight.MetadataRecordBatchReader,
        writer: flight.MetadataRecordBatchWriter,
        return_chunks: bool,
    ) -> int:
        self._unimplemented_exchange_operation(ExchangeOperation.DELETE)

    def exchange_scalar_function(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        descriptor: flight.FlightDescriptor,
        reader: flight.MetadataRecordBatchReader,
        writer: flight.MetadataRecordBatchWriter,
    ) -> None:
        self._unimplemented_exchange_operation(ExchangeOperation.SCALAR_FUNCTION)

    def exchange_table_function_in_out(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        descriptor: flight.FlightDescriptor,
        parameters: parameter_types.TableFunctionParameters,
        input_schema: pa.Schema,
    ) -> tuple[pa.Schema, parameter_types.TableFunctionInOutGenerator]:
        self._unimplemented_exchange_operation(ExchangeOperation.TABLE_FUNCTION_IN_OUT)

    def exchange_update(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        descriptor: flight.FlightDescriptor,
        reader: flight.MetadataRecordBatchReader,
        writer: flight.MetadataRecordBatchWriter,
        return_chunks: bool,
    ) -> int:
        self._unimplemented_exchange_operation(ExchangeOperation.UPDATE)

    def do_exchange(
        self,
        context: flight.ServerCallContext,
        descriptor: flight.FlightDescriptor,
        reader: flight.MetadataRecordBatchReader,
        writer: flight.MetadataRecordBatchWriter,
    ) -> None:
        caller = self.credentials_from_context_(context)

        logger = log.bind(
            **self.auth_logging_items(context, caller),
            descriptor=descriptor,
        )
        try:
            call_context = CallContext(
                context=context,
                caller=caller,
                logger=logger,
            )

            header_middleware = context.get_middleware("headers")
            assert header_middleware
            airport_operation_headers = header_middleware.client_headers.get("airport-operation")

            if airport_operation_headers is None or len(airport_operation_headers) == 0:
                return self.impl_do_exchange(
                    context=call_context,
                    descriptor=descriptor,
                    reader=reader,
                    writer=writer,
                )

            airport_operation = airport_operation_headers[0]
            logger.debug("do_exchange", airport_operation=airport_operation)

            return_chunks_headers = header_middleware.client_headers.get("return-chunks")
            if return_chunks_headers is None or len(return_chunks_headers) == 0:
                raise flight.FlightServerError(
                    "The return-chunks header is required for this operation."
                )
            return_chunks: bool = return_chunks_headers[0] == "1"

            last_metadata: Any = None
            if airport_operation == ExchangeOperation.INSERT:
                keys_inserted = self.exchange_insert(
                    context=call_context,
                    descriptor=descriptor,
                    reader=reader,
                    writer=writer,
                    return_chunks=return_chunks,
                )
                last_metadata = {"total_changed": keys_inserted}
            elif airport_operation == ExchangeOperation.UPDATE:
                keys_updated = self.exchange_update(
                    context=call_context,
                    descriptor=descriptor,
                    reader=reader,
                    writer=writer,
                    return_chunks=return_chunks,
                )
                last_metadata = {"total_changed": keys_updated}
            elif airport_operation == ExchangeOperation.DELETE:
                keys_deleted = self.exchange_delete(
                    context=call_context,
                    descriptor=descriptor,
                    reader=reader,
                    writer=writer,
                    return_chunks=return_chunks,
                )
                last_metadata = {"total_changed": keys_deleted}
            elif airport_operation == ExchangeOperation.SCALAR_FUNCTION:
                self.exchange_scalar_function(
                    context=call_context,
                    descriptor=descriptor,
                    reader=reader,
                    writer=writer,
                )
            elif airport_operation == ExchangeOperation.TABLE_FUNCTION_IN_OUT:
                # The parameters are sent as the first chunk of the read stream
                # as part of the metadata.
                chunk = next(reader)
                assert chunk.data is None
                assert chunk.app_metadata is not None

                parameters = parameter_types.table_function_parameters(chunk.app_metadata)

                output_schema, generator = self.exchange_table_function_in_out(
                    context=call_context,
                    descriptor=descriptor,
                    parameters=parameters,
                    input_schema=reader.schema,
                )

                writer.begin(output_schema)
                # Prime the generator
                generator.send(None)

                def write_batch(
                    generator_output: parameter_types.TableFunctionInOutGeneratorOutput,
                ) -> bool:
                    result_batch, is_finished = generator_output
                    writer.write_with_metadata(
                        result_batch,
                        b"chunk_continues" if not is_finished else b"chunk_finished",
                    )
                    return is_finished

                # This is an input chunk.
                for item in reader:
                    assert item.data is not None
                    is_finished = write_batch(generator.send(item.data))

                    while not is_finished:
                        is_finished = write_batch(generator.send(True))

                try:
                    generator.send(None)
                except StopIteration as e:
                    if e.value is not None:
                        for i, item in enumerate(e.value):
                            write_batch((item, i == len(e.value) - 1))
                    else:
                        # Always send a final empty batch, no matter what the make the client
                        # easier to implement.
                        write_batch(
                            (
                                pa.RecordBatch.from_pylist([], schema=output_schema),
                                True,
                            )
                        )
            else:
                raise flight.FlightServerError(
                    f"Unknown airport-operation header: {airport_operation}"
                )
            if airport_operation not in (
                ExchangeOperation.SCALAR_FUNCTION,
                ExchangeOperation.TABLE_FUNCTION_IN_OUT,
            ):
                writer.write_metadata(msgpack.packb(last_metadata))

            writer.close()
        except Exception as e:
            logger.exception("do_exchange", error=str(e))
            raise

    def impl_do_get(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        ticket: flight.Ticket,
    ) -> flight.RecordBatchStream:
        raise NotImplementedError("impl_do_get not implemented")

    def do_get(
        self, context: flight.ServerCallContext, ticket: flight.Ticket
    ) -> flight.RecordBatchStream:
        caller = self.credentials_from_context_(context)
        logger = log.bind(
            **self.auth_logging_items(context, caller),
        )

        try:
            logger.info("do_get", ticket=ticket)

            call_context = CallContext(
                context=context,
                caller=caller,
                logger=logger,
            )

            return self.impl_do_get(
                context=call_context,
                ticket=ticket,
            )
        except Exception as e:
            logger.exception("do_get", error=str(e))
            raise

    def impl_do_put(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        descriptor: flight.FlightDescriptor,
        reader: flight.MetadataRecordBatchReader,
        writer: flight.FlightMetadataWriter,
    ) -> None:
        raise NotImplementedError("impl_do_put not implemented")

    def do_put(
        self,
        context: flight.ServerCallContext,
        descriptor: flight.FlightDescriptor,
        reader: flight.MetadataRecordBatchReader,
        writer: flight.FlightMetadataWriter,
    ) -> None:
        caller = self.credentials_from_context_(context)
        logger = log.bind(
            **self.auth_logging_items(context, caller),
        )

        try:
            logger.info("do_put", descriptor=descriptor)

            call_context = CallContext(
                context=context,
                caller=caller,
                logger=logger,
            )

            return self.impl_do_put(
                context=call_context,
                descriptor=descriptor,
                reader=reader,
                writer=writer,
            )
        except Exception as e:
            logger.exception("do_put", error=str(e))
            raise
