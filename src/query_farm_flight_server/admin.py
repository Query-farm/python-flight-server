import datetime
import json
import re
from typing import Any

import boto3
import click
from prettytable import PrettyTable
from pydantic import BaseModel, Field

from . import auth_manager as am
from . import auth_manager_dynamodb


def validate_email(ctx: Any, param: Any, value: str) -> str:
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(email_regex, value):
        raise click.BadParameter("Invalid email address.")
    return value


def build(
    *,
    auth_manager: auth_manager_dynamodb.AuthManagerDynamoDB[am.AccountType, am.TokenType],
) -> Any:
    @click.group()
    def cli() -> None:
        pass

    @click.command(help="Create a token for an account")
    @click.option("--account-id", type=str, required=True, help="Account ID")
    def create_token(account_id: str) -> None:
        assert auth_manager.account_by_id(account_id)
        token = auth_manager.create_token(account_id=account_id)
        auth_manager.upsert_token(token)
        print(f"Added token {token.token}")

    @click.command(help="List accounts")
    def list_accounts() -> None:
        accounts = auth_manager.list_accounts()

        t = PrettyTable()
        t.field_names = ["Account ID", "Name", "Email"]
        for account in accounts:
            t.add_row([account.account_id, account.name, account.email])
        print(t)

    @click.command(help="List tokens for an account")
    @click.option("--account-id", type=str, required=True, help="Account ID")
    def list_tokens(account_id: str) -> None:
        tokens = auth_manager.list_tokens_for_account_id(account_id)

        t = PrettyTable()
        t.field_names = ["Token"]
        for token in tokens:
            t.add_row([token.token])
        print(t)

    @click.command(help="API usage by account")
    @click.option("--current-month", is_flag=True, help="Only show the current month")
    def usage_by_account(current_month: bool) -> None:
        dynamodb = boto3.resource("dynamodb", region_name=auth_manager._aws_region)
        rate_limit_table = dynamodb.Table(auth_manager._rate_limit_table_name)

        current_yyyymm = datetime.datetime.now().strftime("%Y%m")

        class RateLimitCount(BaseModel):
            account_id: str
            yyyymm: int
            request_count: int = Field(default=0)
            request_seconds: float
            transferred_bytes: int

        if current_month:
            records = rate_limit_table.scan(
                FilterExpression="yyyymm = :yyyymm",
                ExpressionAttributeValues={":yyyymm": current_yyyymm},
            )["Items"]
        else:
            records = rate_limit_table.scan()["Items"]

        usage = [RateLimitCount(**i) for i in records]

        t = PrettyTable()
        t.field_names = [
            "Account ID",
            "YYYY-MMM",
            "Request Count",
            "Request Seconds",
            "Transferred Bytes",
        ]
        for u in usage:
            t.add_row(
                [
                    u.account_id,
                    u.yyyymm,
                    u.request_count,
                    u.request_seconds,
                    u.transferred_bytes,
                ]
            )
        print(t)

    @click.command(help="Get an account")
    @click.option("--account-id", required=True, type=str)
    def get_account(account_id: str) -> None:
        account = auth_manager.account_by_id(account_id)
        print(account.model_dump_json(indent=1))

    @click.command(help="Update an existing account")
    @click.option("--account-id", required=True, type=str)
    @click.option("--data", required=True, type=click.Path(exists=True))
    def update_account(account_id: str, data: str) -> None:
        with open(data) as reader:
            account_data = json.load(reader)
        account = auth_manager.create_account(**account_data)
        account.account_id = account_id
        auth_manager.upsert_account(account)
        print(f"Updated account {account_id}")

    cli.add_command(list_accounts)
    cli.add_command(get_account)
    cli.add_command(update_account)
    cli.add_command(list_tokens)
    cli.add_command(create_token)
    cli.add_command(usage_by_account)
    return cli
