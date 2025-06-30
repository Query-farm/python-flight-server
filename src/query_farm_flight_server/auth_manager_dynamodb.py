import json
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Literal, TypeVar

import boto3
import structlog
from boto3.dynamodb.conditions import Key
from cache3 import DiskCache
from mypy_boto3_dynamodb.service_resource import Table
from mypy_boto3_dynamodb.type_defs import (
    TableAttributeValueTypeDef,
)

from . import auth
from .auth_manager import AccountType, AuthManager, TokenType

log = structlog.get_logger()


T = TypeVar("T")


@dataclass
class CachingDetails:
    enabled: bool
    timeout: int
    tag: str


CacheType = Literal[
    "account",
    "token",
    "credentials",
]

_default_cache_details: dict[CacheType, CachingDetails] = {
    "account": CachingDetails(enabled=True, timeout=60 * 5, tag="account"),
    "token": CachingDetails(enabled=True, timeout=60 * 5, tag="token"),
    "credentials": CachingDetails(enabled=True, timeout=60, tag="credentials"),
}


def _convert_to_dynamo_format(data: Any) -> Any:
    if isinstance(data, dict):
        return {k: _convert_to_dynamo_format(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_convert_to_dynamo_format(v) for v in data]
    elif isinstance(data, float):
        return Decimal(str(data))  # Convert floats to Decimal
    return data


class AuthManagerDynamoDB(AuthManager[AccountType, TokenType]):
    def __init__(
        self,
        *,
        allow_anonymous_access: bool = False,
        service_prefix: str,
        account_type: type[AccountType],
        token_type: type[TokenType],
        aws_region: str = "us-east-1",
        tokens_table_name: str = "flight_cloud_tokens",
        accounts_table_name: str = "flight_cloud_accounts",
        rate_limit_table_name: str = "flight_cloud_rate_limit",
        tokens_table: Table | None = None,
        accounts_table: Table | None = None,
        cache_details: dict[CacheType, CachingDetails] = _default_cache_details,
    ) -> None:
        self._allow_anonymous_access = allow_anonymous_access
        self._service_prefix = service_prefix
        self._account_type = account_type
        self._token_type = token_type
        self._aws_region = aws_region
        dynamodb = boto3.resource("dynamodb", region_name=aws_region)

        self._tokens_table = tokens_table or dynamodb.Table(tokens_table_name)
        self._accounts_table = accounts_table or dynamodb.Table(accounts_table_name)
        self._rate_limit_table_name = rate_limit_table_name
        self._cache_details = cache_details

        self._cache = DiskCache("~/.cache3", name="flight-cloud-auth-manager.db")

    def allow_anonymous_access(self) -> bool:
        return self._allow_anonymous_access

    def _add_service_prefix(self, value: str) -> str:
        """
        Add a prefix to dynamodb stored values to allow the table to be reused
        by multiple services.
        """
        return f"{self._service_prefix}:{value}"

    def _delete_cache(
        self,
        *,
        key: str,
        type: CacheType,
    ) -> None:
        details = self._cache_details[type]
        if details.enabled:
            self._cache.delete(
                key,
                tag=self._add_service_prefix(details.tag),
            )

    def _get_cache(
        self,
        *,
        key: str,
        type: CacheType,
    ) -> Any:
        details = self._cache_details[type]
        if details.enabled:
            return self._cache.get(
                key,
                tag=self._add_service_prefix(details.tag),
            )
        return None

    def _set_cache(
        self,
        *,
        key: str,
        value: T,
        type: CacheType,
        timeout: float | None = None,
    ) -> T:
        details = self._cache_details[type]
        if details.enabled:
            self._cache.set(
                key,
                value,
                timeout=timeout if timeout is not None else details.timeout,
                tag=self._add_service_prefix(details.tag),
            )
        return value

    def _token_from_dynamodb(
        self,
        dynamodb_item: dict[str, TableAttributeValueTypeDef],
    ) -> TokenType:
        beginning_prefix = f"{self._service_prefix}:"
        return self._token_type(
            **(
                {**dynamodb_item}
                | {
                    "token": str(dynamodb_item["token"]).removeprefix(beginning_prefix),
                    "account_id": str(dynamodb_item["account_id"]).removeprefix(beginning_prefix),
                }
            )
        )

    def create_account(self, **kwargs: Any) -> AccountType:
        return self._account_type(**kwargs)

    def create_token(self, **kwargs: Any) -> TokenType:
        return self._token_type(**kwargs)

    def data_for_token(self, token: str) -> TokenType:
        cached_token = self._get_cache(key=token, type="token")
        if cached_token is not None:
            token_details = self._token_type(**json.loads(cached_token))
        else:
            token_data = self._tokens_table.get_item(Key={"token": self._add_service_prefix(token)})

            if "Item" not in token_data:
                raise auth.TokenUnknown("Token not found")

            # Parse it out into the type with pydantic.
            token_details = self._token_from_dynamodb(token_data["Item"])

            self._set_cache(key=token, value=token_details.model_dump_json(), type="token")

        if token_details.disabled:
            raise auth.TokenDisabled("Token is disabled")

        account_details = self.account_by_id(token_details.account_id)
        if account_details.disabled:
            raise auth.AccountDisabled("Account is disabled")

        return token_details

    def account_by_id(self, account_id: str) -> AccountType:
        assert not account_id.startswith(self._add_service_prefix(""))
        cached_account = self._get_cache(key=account_id, type="account")
        if cached_account is not None:
            account_details = self._account_type(**json.loads(cached_account), auth_manager=self)
        else:
            account_data = self._accounts_table.get_item(
                Key={"account_id": self._add_service_prefix(account_id)}
            )

            if "Item" not in account_data:
                raise auth.AccountUnknown("Account not found: " + account_id)

            # Parse it out into the type with pydantic.
            account_details = self._account_from_dynamodb(account_data["Item"])

            self._set_cache(
                key=account_id,
                value=account_details.model_dump_json(),
                type="account",
            )

        if account_details.disabled:
            raise auth.AccountDisabled("Account is disabled")

        return account_details

    def upsert_token(self, token: TokenType) -> None:
        self._delete_cache(key=token.token, type="token")
        serialized = _convert_to_dynamo_format(token.model_dump(mode="json"))
        self._tokens_table.put_item(
            Item={
                **serialized,
                "token": self._add_service_prefix(token.token),
                "account_id": self._add_service_prefix(token.account_id),
            }
        )

    def upsert_account(self, account: AccountType) -> None:
        self._delete_cache(key=account.account_id, type="account")
        serialized = _convert_to_dynamo_format(account.model_dump(mode="json"))
        self._accounts_table.put_item(
            Item={
                **serialized,
                "account_id": self._add_service_prefix(account.account_id),
            }
        )

    def account_ids_for_email_address(self, email: str) -> list[str]:
        accounts = self._accounts_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq(email),
        )
        return [
            str(v["account_id"]).removeprefix(self._add_service_prefix(""))
            for v in accounts["Items"]
            if str(v["account_id"]).startswith(self._add_service_prefix(""))
        ]

    def list_accounts(self) -> list[AccountType]:
        accounts = self._accounts_table.scan()
        return [
            self._account_from_dynamodb(v)
            for v in accounts["Items"]
            if str(v["account_id"]).startswith(self._add_service_prefix(""))
        ]

    def list_tokens_for_account_id(self, account_id: str) -> list[TokenType]:
        tokens = self._tokens_table.query(
            IndexName="account_id-index",
            KeyConditionExpression=Key("account_id").eq(self._add_service_prefix(account_id)),
        )
        return [self._token_from_dynamodb(v) for v in tokens["Items"]]

    def _account_from_dynamodb(
        self,
        dynamodb_item: dict[str, TableAttributeValueTypeDef],
    ) -> AccountType:
        return self._account_type(
            auth_manager=self,
            **(
                {**dynamodb_item}
                | {
                    "account_id": str(dynamodb_item["account_id"]).removeprefix(
                        self._add_service_prefix("")
                    ),
                }
            ),
        )
