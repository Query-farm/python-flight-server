import functools
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Generic, NoReturn, ParamSpec, TypeVar, cast

import msgpack
import pyarrow.flight as flight
import structlog

from query_farm_server_base import action_decoders

from . import auth, middleware

P = ParamSpec("P")
R = TypeVar("R")


log = structlog.get_logger()

AccountType = TypeVar("AccountType", bound=auth.Account)
TokenType = TypeVar("TokenType", bound=auth.AccountToken)


@dataclass
class CallContext(Generic[AccountType, TokenType]):
    context: flight.ServerCallContext
    caller: middleware.SuppliedCredentials[AccountType, TokenType] | None
    logger: structlog.BoundLogger


# Setup a decorator to log the action and its parameters.
def log_action() -> Callable[[Callable[P, R]], Callable[P, R]]:
    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            func_name = func.__name__

            # Example: log a known kwarg
            if "context" in kwargs:
                context = cast(CallContext[Any, Any], kwargs["context"])
                context.logger.debug(func_name, parameters=kwargs["parameters"])
            return func(*args, **kwargs)

        return wrapper

    return decorator


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
        context: flight.ServerCallContext,
        criteria: bytes,
        caller: middleware.SuppliedCredentials[AccountType, TokenType] | None,
        logger: structlog.BoundLogger,
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

        logger.info("list_flights")

        return self.impl_list_flights(
            context=context,
            criteria=criteria,
            logger=logger,
            caller=caller,
        )

    def impl_get_flight_info(
        self,
        *,
        context: flight.ServerCallContext,
        descriptor: flight.FlightDescriptor,
        caller: middleware.SuppliedCredentials[AccountType, TokenType] | None,
        logger: structlog.BoundLogger,
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
        )

        return self.impl_get_flight_info(
            context=context,
            descriptor=descriptor,
            logger=logger,
            caller=caller,
        )

    def impl_do_action(
        self,
        *,
        action: flight.Action,
        call_context: CallContext[AccountType, TokenType],
    ) -> Iterator[bytes]:
        raise NotImplementedError("impl_do_action not implemented")

    def _unimplemented_action(self, action_name: str) -> NoReturn:
        raise flight.FlightUnavailableError(f"The {action_name} action is not implemented")

    @log_action()
    def action_add_column(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.AddColumnParameters,
    ) -> None:
        self._unimplemented_action("add_column")

    @log_action()
    def action_add_constraint(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.AddConstraintParameters,
    ) -> None:
        self._unimplemented_action("add_constraint")

    @log_action()
    def action_add_field(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.AddFieldParameters,
    ) -> None:
        self._unimplemented_action("add_field")

    @log_action()
    def action_change_column_type(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.ChangeColumnTypeParameters,
    ) -> None:
        self._unimplemented_action("change_column_type")

    # FIXME: build a type for the column statistics, or switch over
    # to an arrow based return set of values.
    @log_action()
    def action_column_statistics(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.ColumnStatisticsParameters,
    ) -> dict[str, Any]:
        self._unimplemented_action("column_statistics")

    @log_action()
    def action_drop_not_null(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.DropNotNullParameters,
    ) -> None:
        self._unimplemented_action("drop_not_null")

    @log_action()
    def action_drop_table(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.DropObjectParameters,
    ) -> None:
        self._unimplemented_action("drop_table")

    @log_action()
    def action_endpoints(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.EndpointsParameters,
    ) -> list[flight.Endpoint]:
        self._unimplemented_action("endpoints")

    @log_action()
    def action_list_schemas(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.ListSchemasParameters,
    ) -> Iterator[bytes]:
        self._unimplemented_action("list_schemas")

    @log_action()
    def action_remove_column(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.RemoveColumnParameters,
    ) -> None:
        self._unimplemented_action("remove_column")

    @log_action()
    def action_remove_field(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.RemoveFieldParameters,
    ) -> None:
        self._unimplemented_action("remove_field")

    @log_action()
    def action_rename_column(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.RenameColumnParameters,
    ) -> None:
        self._unimplemented_action("rename_column")

    @log_action()
    def action_rename_field(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.RenameFieldParameters,
    ) -> None:
        self._unimplemented_action("rename_field")

    @log_action()
    def action_rename_table(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.RenameTableParameters,
    ) -> None:
        self._unimplemented_action("rename_table")

    @log_action()
    def action_set_default(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.SetDefaultParameters,
    ) -> None:
        self._unimplemented_action("set_default")

    @log_action()
    def action_set_not_null(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.SetNotNullParameters,
    ) -> None:
        self._unimplemented_action("set_not_null")

    @log_action()
    def action_table_function_flight_info(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.TableFunctionFlightInfoParameters,
    ) -> flight.FlightInfo:
        self._unimplemented_action("table_function_flight_info")

    @abstractmethod
    def action_catalog_version(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        database_name: str,
    ) -> tuple[int, bool]:
        pass

    @abstractmethod
    @log_action()
    def action_create_transaction(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        database_name: str,
    ) -> str | None:
        pass

    @abstractmethod
    @log_action()
    def action_create_schema(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.CreateSchemaParameters,
    ) -> None:
        pass

    @log_action()
    def action_create_table(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
        parameters: action_decoders.CreateTableParameters,
    ) -> flight.FlightInfo:
        self._unimplemented_action("create_table")

    @abstractmethod
    @log_action()
    def action_drop_schema(
        self,
        *,
        call_context: CallContext[AccountType, TokenType],
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
            action=action,
        )

        logger.info("do_action")

        call_context = CallContext(
            context=context,
            caller=caller,
            logger=logger,
        )

        # Need a function to log the action and the decoded parameters.
        # then call the handler.

        if action.type == "add_column":
            self.action_add_column(
                call_context=call_context,
                parameters=action_decoders.add_column(action),
            )
            return iter([])
        elif action.type == "add_constraint":
            self.action_add_constraint(
                call_context=call_context,
                parameters=action_decoders.add_constraint(action),
            )
            return iter([])
        elif action.type == "add_field":
            self.action_add_field(
                call_context=call_context,
                parameters=action_decoders.add_field(action),
            )
            return iter([])
        elif action.type == "catalog_version":
            return self.pack_result(
                self.action_catalog_version(
                    call_context=call_context,
                    database_name=action.body.to_pybytes().decode("utf-8"),
                )
            )
        elif action.type == "change_column_type":
            self.action_change_column_type(
                call_context=call_context,
                parameters=action_decoders.change_column_type(action),
            )
            return iter([])
        elif action.type == "column_statistics":
            return self.pack_result(
                self.action_column_statistics(
                    call_context=call_context,
                    parameters=action_decoders.column_statistics(action),
                )
            )
        elif action.type == "create_schema":
            self.action_create_schema(
                call_context=call_context,
                parameters=action_decoders.create_schema(action),
            )
            return iter([])
        elif action.type == "create_table":
            return self.pack_result(
                self.action_create_table(
                    call_context=call_context,
                    parameters=action_decoders.create_table(action),
                )
            )
        elif action.type == "create_transaction":
            return iter(
                msgpack.packb(
                    [
                        self.action_create_transaction(
                            call_context=call_context,
                            database_name=action.body.to_pybytes().decode("utf-8"),
                        )
                    ]
                )
            )
        elif action.type == "drop_not_null":
            self.action_drop_not_null(
                call_context=call_context,
                parameters=action_decoders.drop_not_null(action),
            )
            return iter([])
        elif action.type == "drop_table":
            self.action_drop_table(
                call_context=call_context,
                parameters=action_decoders.drop_table(action),
            )
            return iter([])
        elif action.type == "drop_schema":
            self.action_drop_schema(
                call_context=call_context,
                parameters=action_decoders.drop_schema(action),
            )
            return iter([])
        elif action.type == "endpoints":
            return self.pack_result(
                self.action_endpoints(
                    call_context=call_context,
                    parameters=action_decoders.endpoints(action),
                )
            )
        elif action.type == "list_schemas":
            return self.pack_result(
                self.action_list_schemas(
                    call_context=call_context,
                    parameters=action_decoders.list_schemas(action),
                )
            )
        elif action.type == "remove_column":
            self.action_remove_column(
                call_context=call_context,
                parameters=action_decoders.remove_column(action),
            )
            return iter([])
        elif action.type == "remove_field":
            self.action_remove_field(
                call_context=call_context,
                parameters=action_decoders.remove_field(action),
            )
            return iter([])
        elif action.type == "rename_column":
            self.action_rename_column(
                call_context=call_context,
                parameters=action_decoders.rename_column(action),
            )
            return iter([])
        elif action.type == "rename_field":
            self.action_rename_field(
                call_context=call_context,
                parameters=action_decoders.rename_field(action),
            )
            return iter([])
        elif action.type == "rename_table":
            self.action_rename_table(
                call_context=call_context,
                parameters=action_decoders.rename_table(action),
            )
            return iter([])
        elif action.type == "set_default":
            self.action_set_default(
                call_context=call_context,
                parameters=action_decoders.set_default(action),
            )
            return iter([])
        elif action.type == "set_not_null":
            self.action_set_not_null(
                call_context=call_context,
                parameters=action_decoders.set_not_null(action),
            )
            return iter([])
        elif action.type == "table_function_flight_info":
            return self.pack_result(
                self.action_table_function_flight_info(
                    call_context=call_context,
                    parameters=action_decoders.table_function_flight_info(action),
                )
            )
        else:
            logger.debug(action.type)
            return self.impl_do_action(
                call_context=call_context,
                action=action,
            )

    def impl_do_exchange(
        self,
        *,
        context: flight.ServerCallContext,
        descriptor: flight.FlightDescriptor,
        reader: flight.MetadataRecordBatchReader,
        writer: flight.MetadataRecordBatchWriter,
        caller: middleware.SuppliedCredentials[AccountType, TokenType] | None,
        logger: structlog.BoundLogger,
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

        return self.impl_do_exchange(
            context=context,
            descriptor=descriptor,
            reader=reader,
            writer=writer,
            logger=logger,
            caller=caller,
        )

    def impl_do_get(
        self,
        *,
        context: flight.ServerCallContext,
        ticket: flight.Ticket,
        caller: middleware.SuppliedCredentials[AccountType, TokenType] | None,
        logger: structlog.BoundLogger,
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

        return self.impl_do_get(
            context=context,
            ticket=ticket,
            logger=logger,
            caller=caller,
        )

    def impl_do_put(
        self,
        *,
        context: flight.ServerCallContext,
        caller: middleware.SuppliedCredentials[AccountType, TokenType] | None,
        logger: structlog.BoundLogger,
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

        return self.impl_do_put(
            context=context,
            logger=logger,
            caller=caller,
            descriptor=descriptor,
            reader=reader,
            writer=writer,
        )
