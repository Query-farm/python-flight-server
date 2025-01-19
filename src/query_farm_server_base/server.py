from collections.abc import Iterator
from typing import Any

import pyarrow.flight as flight
import structlog

from . import auth, auth_manager, middleware

log = structlog.get_logger()


class Caller:
    def __init__(self, *, account: auth.Account, token: auth.AccountToken) -> None:
        self.account = account
        self.token = token


class BasicFlightServer(flight.FlightServerBase):
    def __init__(
        self,
        *,
        location: str | None,
        auth_manager: auth_manager.AuthManager[auth.Account, auth.AccountToken],
        **kwargs: dict[str, Any],
    ) -> None:
        self._location = location

        super().__init__(location, **kwargs)

    def auth_middleware(
        self, context: flight.ServerCallContext
    ) -> middleware.BasicAuthServerMiddleware[auth.Account, auth.AccountToken]:
        auth_middleware: middleware.BasicAuthServerMiddleware[auth.Account, auth.AccountToken] = context.get_middleware(
            "auth"
        )
        assert isinstance(auth_middleware, middleware.BasicAuthServerMiddleware)
        return auth_middleware

    def caller_from_context_(self, context: flight.ServerCallContext) -> Caller:
        auth_middleware = self.auth_middleware(context)
        return Caller(account=auth_middleware.account, token=auth_middleware.token)

    def auth_logging_items(self, context: flight.ServerCallContext, caller: Caller) -> dict[str, Any]:
        """Return the items that will be bound to the logger."""
        return {
            "token": caller.token,
            "account": caller.account.account_id,
            "address": context.peer(),
        }

    def impl_list_flights(
        self,
        *,
        context: flight.ServerCallContext,
        criteria: bytes,
        caller: Caller,
        logger: structlog.BoundLogger,
    ) -> Iterator[flight.FlightInfo]:
        raise NotImplementedError("impl_list_flights not implemented")

    def list_flights(self, context: flight.ServerCallContext, criteria: bytes) -> Iterator[flight.FlightInfo]:
        caller = self.caller_from_context_(context)

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
        caller: Caller,
        logger: structlog.BoundLogger,
    ) -> flight.FlightInfo:
        raise NotImplementedError("impl_get_flight_info not implemented")

    def get_flight_info(
        self, context: flight.ServerCallContext, descriptor: flight.FlightDescriptor
    ) -> flight.FlightInfo:
        caller = self.caller_from_context_(context)

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
        caller: Caller,
        logger: structlog.BoundLogger,
    ) -> Iterator[bytes]:
        raise NotImplementedError("impl_do_action not implemented")

    def do_action(self, context: flight.ServerCallContext, action: flight.Action) -> Iterator[bytes]:
        caller = self.caller_from_context_(context)

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
        caller: Caller,
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
        caller = self.caller_from_context_(context)

        logger = log.bind(
            **self.auth_logging_items(context, caller),
            descriptor=descriptor,
        )

        logger.info("do_exchange")

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
        caller: Caller,
        logger: structlog.BoundLogger,
    ) -> flight.RecordBatchStream:
        raise NotImplementedError("impl_do_get not implemented")

    def do_get(self, context: flight.ServerCallContext, ticket: flight.Ticket) -> flight.RecordBatchStream:
        caller = self.caller_from_context_(context)

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
        caller: Caller,
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
        caller = self.caller_from_context_(context)

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

    @staticmethod
    def run_server(
        cls: type["BasicFlightServer"],
        *,
        location: str,
        auth_manager: auth_manager.AuthManager[auth.Account, auth.AccountToken],
        **kwargs: dict[str, Any],
    ) -> None:
        log.info("Starting server", location=location)

        server = cls(
            middleware={
                "headers": middleware.SaveHeadersMiddlewareFactory(),
                "auth": middleware.AuthManagerMiddlewareFactory(auth_manager=auth_manager),
            },
            location=location,
            auth_manager=auth_manager,
        )
        server.serve()
