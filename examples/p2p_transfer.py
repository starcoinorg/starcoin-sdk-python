from starcoin import starcoin_types as types
from starcoin import starcoin_stdlib as stdlib
from starcoin import serde_types as st
from starcoin.sdk import (utils, client, local_account, auth_key)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
import time
import typing


def transfer(cli: client.Client, sender: local_account.LocalAccount, payee: str, amount: st.uint128, payee_auth_key=typing.Union[auth_key.AuthKey, None]):
    seq_num = cli.get_account_sequence(sender.account_address)
    payee_account = utils.account_address(payee)
    script = stdlib.encode_peer_to_peer_script(
        token_type=utils.currency_code("STC"),
        payee=payee_account,
        payee_auth_key=payee_auth_key,  # assert the payee address has been on chain
        amount=amount,
    )
    raw_txn = types.RawTransaction(
        sender=sender.account_address,
        sequence_number=seq_num,
        payload=types.TransactionPayload__Script(script),
        max_gas_amount=1_000_000,
        gas_unit_price=1,
        gas_token_code="0x1::STC::STC",
        expiration_timestamp_secs=int(time.time()) + 30,
        chain_id=types.ChainId(st.uint8(2)),
    )
    txn = sender.sign(raw_txn)
    print(cli.submit(txn))


if __name__ == "__main__":
    cli = client.Client("http://proxima1.seed.starcoin.org:9850")
    # sender
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
        "27d6a5ee4d822a94f5455edd439da83e9fb5c37ac914b677fee1128d8c9b074a"))
    sender = local_account.LocalAccount(private_key)

    # reciver
    payee_public_key_hex = "a515e60cc14b18114f794aff6d198fff1c59cf346dc7b6ef9b8898c088589665"
    pk = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(payee_public_key_hex))
    payee_auth_key = auth_key.AuthKey.from_public_key(pk)
    payee_address = payee_auth_key.account_address()
    if not cli.is_account_exist(payee_address):
        payee_auth_key = payee_auth_key.data
    else:
        payee_auth_key = b""

    transfer(cli, sender, payee_address, 100_00_00, payee_auth_key)
    print(cli.get_account_token(payee_address, "STC", "STC"))
