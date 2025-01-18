from collections.abc import Iterator
from typing import Any, Generic, Type, TypeVar

import pyarrow.flight as flight
import structlog

from . import auth, auth_manager, middleware

log = structlog.get_logger()


AuthManager = TypeVar("AuthManager", bound=auth_manager.AuthManager[auth.Account, auth.AccountToken])


class BasicFlightServer(flight.FlightServerBase, Generic[AuthManager]):
    def __init__(
        self,
        location: str | None,
        auth_manager: AuthManager,
        **kwargs: dict[str, Any],
    ) -> None:
        self._location = location
        self._auth_manager = auth_manager

        super().__init__(location, **kwargs)

    def auth_middleware(
        self, context: flight.ServerCallContext
    ) -> middleware.BasicAuthServerMiddleware[auth.Account, auth.AccountToken]:
        auth_middleware: middleware.BasicAuthServerMiddleware[auth.Account, auth.AccountToken] = context.get_middleware(
            "auth"
        )
        assert isinstance(auth_middleware, middleware.BasicAuthServerMiddleware)
        return auth_middleware

    def calling_auth_items(self, context: flight.ServerCallContext) -> tuple[auth.Account, auth.AccountToken]:
        auth_middleware = self.auth_middleware(context)
        return auth_middleware.account, auth_middleware.token

    def auth_logging_items(
        self, context: flight.ServerCallContext, calling_account: auth.Account, calling_token: auth.AccountToken
    ) -> dict[str, Any]:
        return {
            "token": calling_token.token,
            "account": calling_account.account_id,
            "address": context.peer(),
        }

    def impl_list_flights(
        self,
        *,
        context: flight.ServerCallContext,
        criteria: bytes,
        calling_account: auth.Account,
        calling_token: auth.AccountToken,
        logger: structlog.BoundLogger,
    ) -> Iterator[flight.FlightInfo]:
        raise NotImplementedError("impl_list_flights not implemented")

    def list_flights(self, context: flight.ServerCallContext, criteria: bytes) -> Iterator[flight.FlightInfo]:
        calling_account, calling_token = self.calling_auth_items(context)

        logger = log.bind(
            **self.auth_logging_items(context, calling_account, calling_token),
            criteria=criteria,
        )

        logger.info("list_flights")

        return self.impl_list_flights(
            context=context,
            criteria=criteria,
            logger=logger,
            calling_account=calling_account,
            calling_token=calling_token,
        )

    def impl_get_flight_info(
        self,
        *,
        context: flight.ServerCallContext,
        descriptor: flight.FlightDescriptor,
        calling_account: auth.Account,
        calling_token: auth.AccountToken,
        logger: structlog.BoundLogger,
    ) -> flight.FlightInfo:
        raise NotImplementedError("impl_get_flight_info not implemented")

    def get_flight_info(
        self, context: flight.ServerCallContext, descriptor: flight.FlightDescriptor
    ) -> flight.FlightInfo:
        calling_account, calling_token = self.calling_auth_items(context)

        logger = log.bind(
            **self.auth_logging_items(context, calling_account, calling_token),
            descriptor=descriptor,
        )

        logger.info(
            "get_flight_info",
        )

        return self.impl_get_flight_info(
            context=context,
            descriptor=descriptor,
            logger=logger,
            calling_account=calling_account,
            calling_token=calling_token,
        )

    def impl_do_action(
        self,
        *,
        context: flight.ServerCallContext,
        action: flight.Action,
        calling_account: auth.Account,
        calling_token: auth.AccountToken,
        logger: structlog.BoundLogger,
    ) -> Iterator[bytes]:
        raise NotImplementedError("impl_do_action not implemented")

    def do_action(self, context: flight.ServerCallContext, action: flight.Action) -> Iterator[bytes]:
        calling_account, calling_token = self.calling_auth_items(context)

        logger = log.bind(
            **self.auth_logging_items(context, calling_account, calling_token),
            action=action,
        )

        logger.info("do_action")

        return self.impl_do_action(
            context=context,
            action=action,
            logger=logger,
            calling_account=calling_account,
            calling_token=calling_token,
        )

    def impl_do_exchange(
        self,
        *,
        context: flight.ServerCallContext,
        descriptor: flight.FlightDescriptor,
        reader: flight.MetadataRecordBatchReader,
        writer: flight.MetadataRecordBatchWriter,
        calling_account: auth.Account,
        calling_token: auth.AccountToken,
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
        calling_account, calling_token = self.calling_auth_items(context)

        logger = log.bind(
            **self.auth_logging_items(context, calling_account, calling_token),
            descriptor=descriptor,
        )

        logger.info("do_exchange")
        breakpoint()

        return self.impl_do_exchange(
            context=context,
            descriptor=descriptor,
            reader=reader,
            writer=writer,
            logger=logger,
            calling_account=calling_account,
            calling_token=calling_token,
        )

    def impl_do_get(
        self,
        *,
        context: flight.ServerCallContext,
        ticket: flight.Ticket,
        calling_account: auth.Account,
        calling_token: auth.AccountToken,
        logger: structlog.BoundLogger,
    ) -> flight.RecordBatchStream:
        raise NotImplementedError("impl_do_get not implemented")

    def do_get(self, context: flight.ServerCallContext, ticket: flight.Ticket) -> flight.RecordBatchStream:
        calling_account, calling_token = self.calling_auth_items(context)

        logger = log.bind(
            **self.auth_logging_items(context, calling_account, calling_token),
        )

        logger.info("do_get", ticket=ticket)

        return self.impl_do_get(
            context=context,
            ticket=ticket,
            logger=logger,
            calling_account=calling_account,
            calling_token=calling_token,
        )

    @staticmethod
    def run_server(
        cls: type["BasicFlightServer[AuthManager]"],
        *,
        location: str,
        auth_manager: AuthManager,
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
