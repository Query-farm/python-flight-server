import functools
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Generic, NoReturn, ParamSpec, TypeVar, cast

import msgpack
import pyarrow.flight as flight
import structlog
import zstandard as zstd
from pydantic import BaseModel

from query_farm_server_base import action_decoders

from . import auth, middleware

# This is the level of ZStandard compression to use for the top-level schema
# JSON information.
SCHEMA_TOP_LEVEL_COMPRESSION_LEVEL = 12


log = structlog.get_logger()

AccountType = TypeVar("AccountType", bound=auth.Account)
TokenType = TypeVar("TokenType", bound=auth.AccountToken)


@dataclass
class CallContext(Generic[AccountType, TokenType]):
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


class BasicFlightServer(flight.FlightServerBase, Generic[AccountType, TokenType], ABC):
    def __init__(
        self,
        *,
        location: str | None,
        **kwargs: dict[str, Any],
    ) -> None:
        self._location = location
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

    def impl_do_action(
        self,
        *,
        action: flight.Action,
        context: CallContext[AccountType, TokenType],
    ) -> Iterator[bytes]:
        raise NotImplementedError("impl_do_action not implemented")

    def _unimplemented_action(self, action_name: str) -> NoReturn:
        raise flight.FlightUnavailableError(f"The {action_name} action is not implemented")

    def action_add_column(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.AddColumnParameters,
    ) -> None:
        self._unimplemented_action("add_column")

    def action_add_constraint(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.AddConstraintParameters,
    ) -> None:
        self._unimplemented_action("add_constraint")

    def action_add_field(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.AddFieldParameters,
    ) -> None:
        self._unimplemented_action("add_field")

    def action_change_column_type(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.ChangeColumnTypeParameters,
    ) -> None:
        self._unimplemented_action("change_column_type")

    # FIXME: build a type for the column statistics, or switch over
    # to an arrow based return set of values.

    def action_column_statistics(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.ColumnStatisticsParameters,
    ) -> dict[str, Any]:
        self._unimplemented_action("column_statistics")

    def action_drop_not_null(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.DropNotNullParameters,
    ) -> None:
        self._unimplemented_action("drop_not_null")

    def action_drop_table(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.DropObjectParameters,
    ) -> None:
        self._unimplemented_action("drop_table")

    def action_endpoints(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.EndpointsParameters,
    ) -> list[flight.FlightEndpoint]:
        self._unimplemented_action("endpoints")

    def action_list_schemas(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.ListSchemasParameters,
    ) -> AirportSerializedCatalogRoot:
        self._unimplemented_action("list_schemas")

    def action_remove_column(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.RemoveColumnParameters,
    ) -> None:
        self._unimplemented_action("remove_column")

    def action_remove_field(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.RemoveFieldParameters,
    ) -> None:
        self._unimplemented_action("remove_field")

    def action_rename_column(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.RenameColumnParameters,
    ) -> None:
        self._unimplemented_action("rename_column")

    def action_rename_field(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.RenameFieldParameters,
    ) -> None:
        self._unimplemented_action("rename_field")

    def action_rename_table(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.RenameTableParameters,
    ) -> None:
        self._unimplemented_action("rename_table")

    def action_set_default(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.SetDefaultParameters,
    ) -> None:
        self._unimplemented_action("set_default")

    def action_set_not_null(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.SetNotNullParameters,
    ) -> None:
        self._unimplemented_action("set_not_null")

    def action_table_function_flight_info(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.TableFunctionFlightInfoParameters,
    ) -> flight.FlightInfo:
        self._unimplemented_action("table_function_flight_info")

    @abstractmethod
    def action_catalog_version(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.CatalogVersionParameters,
    ) -> GetCatalogVersionResult:
        pass

    @abstractmethod
    def action_create_transaction(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.CreateTransactionParameters,
    ) -> CreateTransactionResult:
        pass

    def action_create_schema(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.CreateSchemaParameters,
    ) -> None:
        pass

    def action_create_table(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.CreateTableParameters,
    ) -> flight.FlightInfo:
        self._unimplemented_action("create_table")

    def action_drop_schema(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        parameters: action_decoders.DropObjectParameters,
    ) -> None:
        self._unimplemented_action("drop_schema")

    def pack_result(self, value: Any) -> Iterator[bytes]:
        return iter([msgpack.packb(value)])

    def do_action(
        self, context: flight.ServerCallContext, action: flight.Action
    ) -> Iterator[bytes]:
        caller = self.credentials_from_context_(context)

        logger = log.bind(
            **self.auth_logging_items(context, caller),
        )

        call_context = CallContext(
            context=context,
            caller=caller,
            logger=logger,
        )

        # Need a function to log the action and the decoded parameters.
        # then call the handler.

        @dataclass
        class ActionHandlerSpec:
            method: Callable[..., Any]
            decoder: Callable[[flight.Action], Any]
            post_transform: Callable[[Any], Any] | None = None
            empty_result: bool = True

        def compress_list_schemas_result(result: AirportSerializedCatalogRoot) -> list[Any]:
            packed_data = msgpack.packb(result.model_dump())
            compressor = zstd.ZstdCompressor(level=SCHEMA_TOP_LEVEL_COMPRESSION_LEVEL)
            compressed_data = compressor.compress(packed_data)
            return [len(packed_data), compressed_data]

        empty_result_action_handlers: dict[str, ActionHandlerSpec] = {
            "add_column": ActionHandlerSpec(self.action_add_column, action_decoders.add_column),
            "add_constraint": ActionHandlerSpec(
                self.action_add_constraint, action_decoders.add_constraint
            ),
            "add_field": ActionHandlerSpec(self.action_add_field, action_decoders.add_field),
            "change_column_type": ActionHandlerSpec(
                self.action_change_column_type, action_decoders.change_column_type
            ),
            "create_schema": ActionHandlerSpec(
                self.action_create_schema, action_decoders.create_schema
            ),
            "drop_not_null": ActionHandlerSpec(
                self.action_drop_not_null, action_decoders.drop_not_null
            ),
            "drop_table": ActionHandlerSpec(self.action_drop_table, action_decoders.drop_table),
            "drop_schema": ActionHandlerSpec(self.action_drop_schema, action_decoders.drop_schema),
            "remove_column": ActionHandlerSpec(
                self.action_remove_column, action_decoders.remove_column
            ),
            "remove_field": ActionHandlerSpec(
                self.action_remove_field, action_decoders.remove_field
            ),
            "rename_column": ActionHandlerSpec(
                self.action_rename_column, action_decoders.rename_column
            ),
            "rename_field": ActionHandlerSpec(
                self.action_rename_field, action_decoders.rename_field
            ),
            "rename_table": ActionHandlerSpec(
                self.action_rename_table, action_decoders.rename_table
            ),
            "set_default": ActionHandlerSpec(self.action_set_default, action_decoders.set_default),
            "set_not_null": ActionHandlerSpec(
                self.action_set_not_null, action_decoders.set_not_null
            ),
            "column_statistics": ActionHandlerSpec(
                self.action_column_statistics, action_decoders.column_statistics, None, False
            ),
            "create_table": ActionHandlerSpec(
                self.action_create_table,
                action_decoders.create_table,
                lambda x: x.serialize(),
                False,
            ),
            "endpoints": ActionHandlerSpec(
                self.action_endpoints,
                action_decoders.endpoints,
                lambda x: [e.serialize() for e in x],
                False,
            ),
            "table_function_flight_info": ActionHandlerSpec(
                self.action_table_function_flight_info,
                action_decoders.table_function_flight_info,
                None,
                False,
            ),
            "list_schemas": ActionHandlerSpec(
                self.action_list_schemas,
                action_decoders.list_schemas,
                compress_list_schemas_result,
                False,
            ),
            "catalog_version": ActionHandlerSpec(
                self.action_catalog_version, action_decoders.catalog_version, None, False
            ),
            "create_transaction": ActionHandlerSpec(
                self.action_create_transaction,
                action_decoders.create_transaction,
                None,
                False,
            ),
        }

        if handler := empty_result_action_handlers.get(action.type):
            parameters = handler.decoder(action)
            logger.debug(action.type, parameters=parameters)

            result = handler.method(context=call_context, parameters=parameters)
            if handler.post_transform:
                result = handler.post_transform(result)
            if handler.empty_result:
                return iter([])
            return self.pack_result(result)

        logger.debug(action.type, action=action)
        return self.impl_do_action(
            context=call_context,
            action=action,
        )

    def impl_do_exchange(
        self,
        *,
        context: CallContext[AccountType, TokenType],
        descriptor: flight.FlightDescriptor,
        reader: flight.MetadataRecordBatchReader,
        writer: flight.MetadataRecordBatchWriter,
    ) -> None:
        raise NotImplementedError("impl_do_exchange not implemented")

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

        call_context = CallContext(
            context=context,
            caller=caller,
            logger=logger,
        )

        return self.impl_do_exchange(
            context=call_context,
            descriptor=descriptor,
            reader=reader,
            writer=writer,
        )

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
