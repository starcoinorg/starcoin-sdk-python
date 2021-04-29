from starcoin.sdk import client
from starcoin import starcoin_types
from starcoin import starcoin_stdlib
cli = client.Client("http://123.56.9.161:9850")


def test_apis():
    status = cli.node_status()
    assert status is True
    assert cli.node_info().get("net") == "barnard"
    account_resource = cli.state_get(
        '0x00000000000000000000000000000001/1/0x00000000000000000000000000000001::Account::Account')
    auth_key = bytes(starcoin_types.AccountResource.bcs_deserialize(
        bytes(account_resource)).authentication_key).hex()
    assert auth_key == "0000000000000000000000000000000000000000000000000000000000000000"
    assert isinstance(cli.get_account_sequence(
        "0x00000000000000000000000000000001"), int) is True
    assert cli.get_account_token(
        "0x00000000000000000000000000000001", "STC", "STC") == 0
    tx = cli.get_transaction(
        "0xd15e5d2d306c898effe61ce9cddb976b8e5a5c24ef67fb5c3a02ca7f156b738b")
    payload = tx.get("user_transaction").get("raw_txn").get("payload")
    payload = bytes.fromhex(payload[2:])
    payload = starcoin_types.TransactionPayload.bcs_deserialize(payload)
    script = starcoin_stdlib.decode_peer_to_peer_script_function(payload.value)
    print(script)
