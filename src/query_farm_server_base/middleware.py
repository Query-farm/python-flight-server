from typing import Any, Generic, TypeVar

import pyarrow.flight as flight
import sentry_sdk

from . import auth
from . import auth_manager as m


class SaveHeadersMiddleware(flight.ServerMiddleware):
    """Store the headers in the middleware for later inspection."""

    def __init__(self, client_headers: dict[str, Any]) -> None:
        self.client_headers = client_headers

        sentry_sdk.set_context("headers", client_headers)


class SaveHeadersMiddlewareFactory(flight.ServerMiddlewareFactory):
    """Test sending/receiving multiple (binary-valued) headers."""

    def start_call(self, info: Any, headers: dict[str, Any]) -> SaveHeadersMiddleware:
        return SaveHeadersMiddleware(headers)


AccountType = TypeVar("AccountType", bound=auth.Account)
TokenType = TypeVar("TokenType", bound=auth.AccountToken)


class BasicAuthServerMiddleware(Generic[AccountType, TokenType], flight.ServerMiddleware):
    """Middleware that implements username-password authentication."""

    def __init__(self, token: TokenType, account: AccountType) -> None:
        self.token = token
        self.account = account

    def sending_headers(self) -> dict[str, str]:
        """Return the authentication token to the client."""
        return {"authorization": f"Bearer {self.token.token}"}


class AuthManagerMiddlewareFactory(Generic[AccountType, TokenType], flight.ServerMiddlewareFactory):
    def __init__(
        self,
        *,
        auth_manager: m.AuthManager[AccountType, TokenType],
    ) -> None:
        self.auth_manager = auth_manager
        pass

    def start_call(
        self, info: flight.CallInfo, headers: dict[str, list[str]]
    ) -> BasicAuthServerMiddleware[AccountType, TokenType]:
        """Validate credentials at the start of every call."""
        # Search for the authentication header (case-insensitive)
        auth_header = None
        for header in headers:
            if header.lower() == "authorization":
                auth_header = headers[header][0]
                break

        if not auth_header:
            raise flight.FlightUnauthenticatedError("No credentials supplied")

        auth_type, _, value = auth_header.partition(" ")

        if auth_type == "Bearer":
            try:
                token_record = self.auth_manager.data_for_token(value)
                account = self.auth_manager.account_by_id(token_record.account_id)

                sentry_sdk.set_context(
                    "auth_info",
                    {
                        "token": value,
                    },
                )

                sentry_sdk.set_user(
                    {
                        "id": account.account_id,
                        "email": account.email,
                    }
                )

                # Change the user for this API call.

                return BasicAuthServerMiddleware(token_record, account)
            except auth.TokenUnknown:
                raise flight.FlightUnauthorizedError("Invalid token") from None
            except auth.TokenDisabled:
                raise flight.FlightUnauthorizedError("Token is disabled") from None
            except auth.AccountDisabled:
                raise flight.FlightUnauthorizedError("Account is disabled") from None

        sentry_sdk.set_user(None)
        raise flight.FlightUnauthenticatedError("No authorization credentials supplied")
