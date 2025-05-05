import os
from collections.abc import Generator, Sequence
from typing import TypedDict

import boto3
import pytest
from moto import mock_aws
from mypy_boto3_dynamodb.service_resource import Table
from mypy_boto3_dynamodb.type_defs import (
    AttributeDefinitionTypeDef,
    KeySchemaElementTypeDef,
)

from . import auth
from . import auth_manager_dynamodb as auth_manager_dynamodb


def test_create_auth_manager() -> None:
    auth_manager = auth_manager_dynamodb.AuthManagerDynamoDB[auth.Account, auth.AccountToken](
        service_prefix="fake-test",
        account_type=auth.Account,
        token_type=auth.AccountToken,
    )
    assert auth_manager is not None


class MockedTables(TypedDict):
    tokens: Table
    accounts: Table


@pytest.fixture(scope="function")
@mock_aws(config={"core": {"mock_credentials": False, "reset_boto3_session": True}})
def mocked_dynamodb_tables() -> Generator[MockedTables, None, None]:
    # Start the mock DynamoDB service

    table_definitions: list[
        tuple[
            str,
            Sequence[KeySchemaElementTypeDef],
            Sequence[AttributeDefinitionTypeDef],
        ],
    ] = [
        (
            "flight_cloud_tokens",
            [{"AttributeName": "token", "KeyType": "HASH"}],
            [{"AttributeName": "token", "AttributeType": "S"}],
        ),
        (
            "flight_cloud_accounts",
            [{"AttributeName": "account_id", "KeyType": "HASH"}],
            [{"AttributeName": "account_id", "AttributeType": "S"}],
        ),
    ]

    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

    all_tables = {}

    for table_name, key_schema, attribute_definition in table_definitions:
        table = dynamodb.create_table(
            TableName=f"test_{table_name}",
            KeySchema=key_schema,
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=attribute_definition,
        )

        # Wait until the table exists
        #        table.meta.client.get_waiter("table_exists").wait(TableName=table_name)

        all_tables[table_name] = table

    # Create a global secondary index on the email field of the accounts table

    all_tables["flight_cloud_accounts"].update(
        AttributeDefinitions=[
            {"AttributeName": "email", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexUpdates=[
            {
                "Create": {
                    "IndexName": "email-index",
                    "KeySchema": [
                        {"AttributeName": "email", "KeyType": "HASH"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            },
        ],
    )

    # Create a global secondary index on the tokens table for the account_id field

    all_tables["flight_cloud_tokens"].update(
        AttributeDefinitions=[
            {"AttributeName": "account_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexUpdates=[
            {
                "Create": {
                    "IndexName": "account_id-index",
                    "KeySchema": [
                        {"AttributeName": "account_id", "KeyType": "HASH"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            },
        ],
    )

    yield MockedTables(
        tokens=all_tables["flight_cloud_tokens"],
        accounts=all_tables["flight_cloud_accounts"],
    )


@pytest.mark.moto
@pytest.mark.filterwarnings("ignore:datetime.datetime.utcnow")
@mock_aws(config={"core": {"mock_credentials": False, "reset_boto3_session": True}})
def test_mocked_auth(
    mocked_dynamodb_tables: Generator[MockedTables, None, None],
) -> None:
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ["AWS_ACCESS_KEY_ID"] = "fake"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "fake"
    tables = next(mocked_dynamodb_tables)
    auth_manager = auth_manager_dynamodb.AuthManagerDynamoDB[auth.Account, auth.AccountToken](
        service_prefix="fake-test",
        tokens_table=tables["tokens"],
        accounts_table=tables["accounts"],
        account_type=auth.Account,
        token_type=auth.AccountToken,
    )
    accounts = auth_manager.list_accounts()
    assert len(accounts) == 0

    test_email_address = "test@example.com"

    account = auth.Account(
        name="test",
        email="test@example.com",
    )
    auth_manager.upsert_account(account)
    accounts = auth_manager.list_accounts()
    assert len(accounts) == 1

    account_data = auth_manager.account_by_id(account.account_id)
    assert account_data is not None

    with pytest.raises(auth.AccountUnknown, match="Account not found"):
        auth_manager.account_by_id(f"test_{account.account_id}")

    existing_accounts = auth_manager.account_ids_for_email_address(test_email_address)
    assert len(existing_accounts) == 1

    token = auth.AccountToken(account_id=account.account_id)
    auth_manager.upsert_token(token)

    tokens = auth_manager.list_tokens_for_account_id(account.account_id)
    assert len(tokens) == 1

    token_data = auth_manager.data_for_token(token.token)
    assert token_data is not None

    with pytest.raises(auth.TokenUnknown, match="Token not found"):
        auth_manager.data_for_token(f"test_{token.token}")

    token_data.disabled = True
    auth_manager.upsert_token(token_data)

    with pytest.raises(auth.TokenDisabled, match="Token is disabled"):
        auth_manager.data_for_token(token.token)

    token_data.disabled = False
    auth_manager.upsert_token(token_data)

    account.disabled = True
    auth_manager.upsert_account(account)

    with pytest.raises(auth.AccountDisabled, match="Account is disabled"):
        auth_manager.data_for_token(token.token)

    account.disabled = False
    auth_manager.upsert_account(account)
