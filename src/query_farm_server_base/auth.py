import uuid
from datetime import UTC, datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field


class AccountToken(BaseModel):
    token: str = Field(default_factory=lambda: uuid.uuid4().hex)
    account_id: str
    last_used: datetime | None = Field(default=None)
    disabled: bool | None = Field(default=False)
    created: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Account(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    account_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    email: str
    name: str
    monthly_request_limit: int = Field(default=-1)
    monthly_transfer_limit: float = Field(default=-1)
    monthly_request_seconds_limit: Decimal = Field(default=Decimal(-1))

    disabled: bool | None = Field(default=False)
    created: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expiration: datetime | None = Field(default=None)


class TokenDisabled(Exception):
    pass


class TokenUnknown(Exception):
    pass


class AccountDisabled(Exception):
    pass


class AccountUnknown(Exception):
    pass
