from dataclasses import dataclass
from typing import Any, TypeVar

import pyarrow.flight as flight
import sentry_sdk

from . import auth, auth_manager


class SaveHeadersMiddleware(flight.ServerMiddleware):
    """Store the headers in the middleware for later inspection."""

    def __init__(self, client_headers: dict[str, Any]) -> None:
        self.client_headers = client_headers

        sentry_sdk.set_context("headers", client_headers)


class SaveHeadersMiddlewareFactory(flight.ServerMiddlewareFactory):
    def start_call(self, info: Any, headers: dict[str, Any]) -> SaveHeadersMiddleware:
        return SaveHeadersMiddleware(headers)


AccountType = TypeVar("AccountType", bound=auth.Account)
TokenType = TypeVar("TokenType", bound=auth.AccountToken)


@dataclass
class SuppliedCredentials[AccountType: auth.Account, TokenType: auth.AccountToken]:
    def __init__(self, token: TokenType, account: AccountType) -> None:
        assert token
        assert account
        self.token = token
        self.account = account


class SaveCredentialsMiddleware(
    SuppliedCredentials[AccountType, TokenType], flight.ServerMiddleware
):
    """Middleware that saves the token and account if supplied."""

    def __init__(self, credentials: SuppliedCredentials[AccountType, TokenType] | None) -> None:
        self.credentials = credentials

    def sending_headers(self) -> dict[str, str]:
        """Return the authentication token to the client."""
        if self.credentials is None:
            return {}
        return {"authorization": f"Bearer {self.credentials.token.token}"}


class AuthManagerMiddlewareFactory[AccountType: auth.Account, TokenType: auth.AccountToken](
    flight.ServerMiddlewareFactory
):
    def __init__(
        self,
        *,
        auth_manager: auth_manager.AuthManager[AccountType, TokenType],
    ) -> None:
        self.auth_manager = auth_manager
        pass

    def start_call(
        self, info: flight.CallInfo, headers: dict[str, list[str]]
    ) -> SaveCredentialsMiddleware[AccountType, TokenType]:
        """Validate credentials at the start of every call."""
        # Search for the authentication header (case-insensitive)
        auth_header = None
        for header in headers:
            if header.lower() == "authorization":
                auth_header = headers[header][0]
                break

        # If there is no auth manager no point in saving the credentials if they
        # are supplied.
        if not self.auth_manager:
            return SaveCredentialsMiddleware(None)

        if not auth_header:
            if not self.auth_manager.allow_anonymous_access():
                raise flight.FlightUnauthenticatedError("No credentials supplied")
            else:
                # Allow anonymous access
                return SaveCredentialsMiddleware(None)

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

                return SaveCredentialsMiddleware(SuppliedCredentials(token_record, account))
            except auth.TokenUnknown:
                raise flight.FlightUnauthorizedError("Invalid token") from None
            except auth.TokenDisabled:
                raise flight.FlightUnauthorizedError("Token is disabled") from None
            except auth.AccountDisabled:
                raise flight.FlightUnauthorizedError("Account is disabled") from None
        raise flight.FlightUnauthenticatedError("Invalid authentication type")
