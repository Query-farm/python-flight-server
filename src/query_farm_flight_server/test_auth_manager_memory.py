
import pytest

from . import auth, auth_manager_memory


def test_create_auth_manager() -> None:
    auth_manager = auth_manager_memory.AuthManagerMemory[auth.Account, auth.AccountToken](
        account_type=auth.Account,
        token_type=auth.AccountToken,
        allow_anonymous_access=False,
    )
    assert auth_manager is not None


@pytest.mark.filterwarnings("ignore:datetime.datetime.utcnow")
def test_mocked_auth() -> None:
    auth_manager = auth_manager_memory.AuthManagerMemory[auth.Account, auth.AccountToken](
        account_type=auth.Account,
        token_type=auth.AccountToken,
        allow_anonymous_access=False,
    )
    accounts = auth_manager.list_accounts()
    assert len(accounts) == 0

    test_email_address = "test@example.com"

    account = auth_manager.create_account(
        name="test",
        email=test_email_address,
    )

    accounts = auth_manager.list_accounts()
    assert len(accounts) == 1

    account_data = auth_manager.account_by_id(account.account_id)
    assert account_data is not None

    with pytest.raises(auth.AccountUnknown, match="Account not found"):
        auth_manager.account_by_id(f"test_{account.account_id}")

    existing_accounts = auth_manager.account_ids_for_email_address(test_email_address)
    assert len(existing_accounts) == 1

    token = auth_manager.create_token(account_id=account.account_id)

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
