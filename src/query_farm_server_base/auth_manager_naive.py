from typing import TypeVar

import structlog

from . import auth_manager_memory
from .auth_manager import AccountType, TokenType

log = structlog.get_logger()

T = TypeVar("T")


class AuthManagerNaive(auth_manager_memory.AuthManagerMemory[AccountType, TokenType]):
    """
    A naive implementation of the AuthManager that creates accounts and tokens based on
    what its called with.  This is useful for testing and development purposes, but should not be used
    in production.
    """

    def __init__(
        self,
        *,
        account_type: type[AccountType],
        token_type: type[TokenType],
        allow_anonymous_access: bool,
    ) -> None:
        super().__init__(
            account_type=account_type,
            token_type=token_type,
            allow_anonymous_access=allow_anonymous_access,
        )

    def data_for_token(self, token: str) -> TokenType:
        if self.tokens.get(token) is None:
            self.upsert_token(self._token_type(token=token, account_id=token))
            self.upsert_account(
                self._account_type(
                    account_id=token, email="example@example.com", name="Dynamic Account"
                )
            )
        return super().data_for_token(token)

    def account_by_id(self, account_id: str) -> AccountType:
        if self.accounts.get(account_id) is None:
            self.upsert_account(
                self._account_type(
                    account_id=account_id, email="example@example.com", name="Dynamic Account"
                )
            )
        return super().account_by_id(account_id)
