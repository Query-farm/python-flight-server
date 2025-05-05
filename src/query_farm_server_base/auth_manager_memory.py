from typing import Any, TypeVar

import structlog

from . import auth
from .auth_manager import AccountType, AuthManager, TokenType

log = structlog.get_logger()

T = TypeVar("T")


class AuthManagerMemory(AuthManager[AccountType, TokenType]):
    def __init__(
        self,
        *,
        account_type: type[AccountType],
        token_type: type[TokenType],
        allow_anonymous_access: bool,
    ) -> None:
        self._allow_anonymous_access = allow_anonymous_access
        self._account_type = account_type
        self._token_type = token_type
        self.tokens: dict[str, TokenType] = {}
        self.accounts: dict[str, AccountType] = {}

    def allow_anonymous_access(self) -> bool:
        return self._allow_anonymous_access

    def create_account(self, **kwargs: Any) -> AccountType:
        account = self._account_type(**kwargs)
        self.accounts[account.account_id] = account
        return account

    def create_token(self, **kwargs: Any) -> TokenType:
        token = self._token_type(**kwargs)
        self.tokens[token.token] = token
        return token

    def data_for_token(self, token: str) -> TokenType:
        token_object = self.tokens.get(token)
        if token_object is None:
            raise auth.TokenUnknown("Token not found: " + token)
        if token_object.disabled:
            raise auth.TokenDisabled("Token is disabled: " + token)
        account = self.account_by_id(token_object.account_id)
        if account.disabled:
            raise auth.AccountDisabled("Account is disabled: " + token_object.account_id)
        return token_object

    def account_by_id(self, account_id: str) -> AccountType:
        account = self.accounts.get(account_id)
        if account is None:
            raise auth.AccountUnknown("Account not found: " + account_id)
        if account.disabled:
            raise auth.AccountDisabled("Account is disabled: " + account_id)
        return account

    def account_ids_for_email_address(self, email: str) -> list[str]:
        return [account.account_id for account in self.accounts.values() if account.email == email]

    def list_accounts(self) -> list[AccountType]:
        return list(self.accounts.values())

    def list_tokens_for_account_id(self, account_id: str) -> list[TokenType]:
        return [token for token in self.tokens.values() if token.account_id == account_id]

    def upsert_token(self, token: TokenType) -> None:
        self.tokens[token.token] = token

    def upsert_account(self, account: AccountType) -> None:
        self.accounts[account.account_id] = account
