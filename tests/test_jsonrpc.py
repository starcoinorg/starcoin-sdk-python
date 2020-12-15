from starcoin.sdk import client
from starcoin.sdk import utils
from starcoin import starcoin_types
cli = client.Client("http://proxima1.seed.starcoin.org:9850")


def test_node_api():
    status = cli.node_status()
    assert status is True
    assert cli.node_info().get("net") == "proxima"


def test_chain_api():
    payload_raw = cli.get_transaction(
        "0x6c52e4fee383b938f4ccb50e575b416c1596257b6c1e85ede80cde7584aec9c9")["user_transaction"]["raw_txn"]["payload"]
    payload = utils.payload_lcs_decode(payload_raw)
    assert type(payload) == starcoin_types.Script
    assert cli.is_account_exist("0x22cad4c80415fd0d56f8652785fcda35") is True
