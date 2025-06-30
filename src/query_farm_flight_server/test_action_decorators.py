from collections.abc import Iterator
from typing import Any

import pyarrow.flight as flight

from query_farm_flight_server import parameter_types

from . import auth, auth_manager, server


def test_action_decorators() -> None:
    class TestFlightServer(server.BasicFlightServer[auth.Account, auth.AccountToken]):
        def __init__(
            self,
            *,
            location: str | None,
            auth_manager: auth_manager.AuthManager[auth.Account, auth.AccountToken] | None,
            **kwargs: dict[str, Any],
        ) -> None:
            self.service_name = "test_server"
            self._auth_manager = auth_manager
            super().__init__(location=location, **kwargs)

        def impl_list_flights(
            self,
            *,
            context: server.CallContext[auth.Account, auth.AccountToken],
            criteria: bytes,
        ) -> Iterator[flight.FlightInfo]:
            raise NotImplementedError("impl_list_flights not implemented")

        def action_create_transaction(
            self,
            *,
            context: server.CallContext[auth.Account, auth.AccountToken],
            parameters: parameter_types.CreateTransaction,
        ) -> server.CreateTransactionResult:
            return server.CreateTransactionResult(identifier="fake")

        def impl_get_flight_info(
            self,
            *,
            context: server.CallContext[auth.Account, auth.AccountToken],
            descriptor: flight.FlightDescriptor,
        ) -> flight.FlightInfo:
            raise NotImplementedError("impl_get_flight_info not implemented")

        def action_catalog_version(
            self,
            *,
            context: server.CallContext[auth.Account, auth.AccountToken],
            parameters: parameter_types.CatalogVersion,
        ) -> server.GetCatalogVersionResult:
            raise NotImplementedError("action_catalog_version not implemented")

        def impl_do_action(
            self,
            *,
            context: server.CallContext[auth.Account, auth.AccountToken],
            action: flight.Action,
        ) -> Iterator[bytes]:
            raise NotImplementedError("impl_do_action not implemented")

        def impl_do_exchange(
            self,
            *,
            context: server.CallContext[auth.Account, auth.AccountToken],
            descriptor: flight.FlightDescriptor,
            reader: flight.MetadataRecordBatchReader,
            writer: flight.MetadataRecordBatchWriter,
        ) -> None:
            pass

        def impl_do_get(
            self,
            *,
            context: server.CallContext[auth.Account, auth.AccountToken],
            ticket: flight.Ticket,
        ) -> flight.RecordBatchStream:
            pass

    test_server = TestFlightServer(location="grpc://localhost:10244", auth_manager=None)
    assert test_server is not None
