from collections.abc import Iterator
from typing import Any, Generic, TypeVar

import pyarrow.flight as flight
import structlog

from . import auth, middleware

log = structlog.get_logger()

AccountType = TypeVar("AccountType", bound=auth.Account)
TokenType = TypeVar("TokenType", bound=auth.AccountToken)


class BasicFlightServer(flight.FlightServerBase, Generic[AccountType, TokenType]):
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
        context: flight.ServerCallContext,
        action: flight.Action,
        caller: middleware.SuppliedCredentials[AccountType, TokenType] | None,
        logger: structlog.BoundLogger,
    ) -> Iterator[bytes]:
        raise NotImplementedError("impl_do_action not implemented")

    def do_action(
        self, context: flight.ServerCallContext, action: flight.Action
    ) -> Iterator[bytes]:
        caller = self.credentials_from_context_(context)

        logger = log.bind(
            **self.auth_logging_items(context, caller),
            action=action,
        )

        logger.info("do_action")

        return self.impl_do_action(
            context=context,
            action=action,
            logger=logger,
            caller=caller,
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
