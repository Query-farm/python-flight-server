from abc import ABC, abstractmethod
from typing import Any, TypeVar

import structlog

from . import auth

log = structlog.get_logger()

T = TypeVar("T")

AccountType = TypeVar("AccountType", bound=auth.Account)
TokenType = TypeVar("TokenType", bound=auth.AccountToken)


# This is your virtual base class
class AuthManager[AccountType: auth.Account, TokenType: auth.AccountToken](ABC):
    @abstractmethod
    def allow_anonymous_access(self) -> bool:
        """Return True if anonymous access is allowed."""
        pass

    @abstractmethod
    def create_account(self, **kwargs: Any) -> AccountType:
        pass

    @abstractmethod
    def create_token(self, **kwargs: Any) -> TokenType:
        pass

    @abstractmethod
    def data_for_token(self, token: str) -> TokenType:
        pass

    @abstractmethod
    def account_by_id(self, account_id: str) -> AccountType:
        pass

    @abstractmethod
    def account_ids_for_email_address(self, email: str) -> list[str]:
        pass

    @abstractmethod
    def list_accounts(self) -> list[AccountType]:
        pass

    @abstractmethod
    def list_tokens_for_account_id(self, account_id: str) -> list[TokenType]:
        pass

    @abstractmethod
    def upsert_token(self, token: TokenType) -> None:
        pass

    @abstractmethod
    def upsert_account(self, account: AccountType) -> None:
        pass
