from starcoin.sdk import client
from starcoin import starcoin_types
from starcoin import lcs
cli = client.Client("http://barnard1.seed.starcoin.org:9850")


def test_apis():
    status = cli.node_status()
    assert status is True
    assert cli.node_info().get("net") == "barnard"
    account_resource = cli.state_get(
        '0x00000000000000000000000000000001/1/0x00000000000000000000000000000001::Account::Account')
    auth_key = bytes(starcoin_types.AccountResource.lcs_deserialize(
        account_resource).authentication_key).hex()
    assert auth_key == "0000000000000000000000000000000000000000000000000000000000000000"
    assert isinstance(cli.get_account_sequence(
        "0x00000000000000000000000000000001"), int) == True
    assert cli.get_account_token(
        "0x00000000000000000000000000000001", "STC", "STC") == 0
