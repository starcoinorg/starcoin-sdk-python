from starcoin import starcoin_types as types
from starcoin import starcoin_stdlib as stdlib
from starcoin import serde_types as st
from starcoin.sdk import (utils, client, local_account, auth_key)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
import time
import typing


def transfer(cli: client.Client, sender: local_account.LocalAccount, payee: str, amount: st.uint128, payee_auth_key=typing.Union[auth_key.AuthKey, None]):
    seq_num = cli.get_account_sequence(
        "0x"+sender.account_address.bcs_serialize().hex())
    payee_account = utils.account_address(payee)
    script = stdlib.encode_peer_to_peer_script_function(
        token_type=utils.currency_code("STC"),
        payee=payee_account,
        payee_auth_key=payee_auth_key,  # assert the payee address has been on chain
        amount=amount,
    )
    node_info = cli.node_info()
    now_seconds = int(node_info.get('now_seconds'))
    # expired after 12 hours
    expiration_timestamp_secs = now_seconds + 43200
    raw_txn = types.RawTransaction(
        sender=sender.account_address,
        sequence_number=seq_num,
        payload=script,
        max_gas_amount=10000000,
        gas_unit_price=1,
        gas_token_code="0x1::STC::STC",
        expiration_timestamp_secs=expiration_timestamp_secs,
        chain_id=types.ChainId(st.uint8(251)),
    )

    txn = sender.sign(raw_txn)
    print(cli.submit(txn))


if __name__ == "__main__":
    cli = client.Client("http://barnard1.seed.starcoin.org:9850")
    # sender
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
        "e424e16db235e3f3b9ef2475516c51d4c15aa5287ceb364213698bd551eab4f2"))
    sender = local_account.LocalAccount(private_key)

    # reciver
    payee_public_key_hex = "a1d2f3e34563ef6e63e0d01e91bd53e9d27da758b25b01771572c240cb4f3113"
    pk = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(payee_public_key_hex))
    payee_auth_key = auth_key.AuthKey.from_public_key(pk)
    payee_address = payee_auth_key.account_address()
    if cli.is_account_exist("0x"+payee_address.bcs_serialize().hex()):
        payee_auth_key = auth_key.AuthKey(b"")
    transfer(cli, sender, payee_address, 1024, payee_auth_key.data)
    print(cli.get_account_token(
        utils.account_address_hex(payee_address), "STC", "STC"))
