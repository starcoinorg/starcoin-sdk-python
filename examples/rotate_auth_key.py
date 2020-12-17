from starcoin import starcoin_types as types
from starcoin import starcoin_stdlib as stdlib
from starcoin import serde_types as st
from starcoin.sdk import (utils, client, local_account, auth_key)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
import time


def rotate_key(cli: client.Client, account: local_account.LocalAccount, auth_key: auth_key.AuthKey):
    seq_num = cli.get_account_sequence(account.account_address)
    script = stdlib.encode_rotate_authentication_key_script(new_auth_key.data)
    raw_txn = types.RawTransaction(
        sender=account.account_address,
        sequence_number=seq_num,
        payload=types.TransactionPayload__Script(script),
        max_gas_amount=1_000_000,
        gas_unit_price=1,
        gas_token_code="0x1::STC::STC",
        expiration_timestamp_secs=int(time.time()) + 30,
        chain_id=types.ChainId(st.uint8(2)),
    )
    txn = account.sign(raw_txn)
    print(cli.submit(txn))


if __name__ == "__main__":

    cli = client.Client("http://proxima1.seed.starcoin.org:9850")
    private_key_hex = "set your private key here"
    new_public_key_hex = "set your new private key here"
    # sender
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
        private_key_hex))
    account = local_account.LocalAccount(private_key)

    # new auth key
    pk = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(new_public_key_hex))
    new_auth_key = auth_key.AuthKey.from_public_key(pk)
    rotate_key(cli, account, new_auth_key)
