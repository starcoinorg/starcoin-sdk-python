import starcoin_types as types
import starcoin_stdlib as stdlib
import serde_types as st
from sdk.local_account import LocalAccount
from sdk import (utils, client)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import time


def transfer(sender: LocalAccount, payee: str, seq_num: st.uint64, amount: st.uint128):
    payee_account = utils.account_address(payee)
    script = stdlib.encode_peer_to_peer_script(
        token_type=utils.currency_code("STC"),
        payee=payee_account,
        payee_auth_key=b"",  # assert the payee address has been on chain
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
    cli = client.Client("http://sanlee1:9850")

    print(cli.submit(txn))


if __name__ == "__main__":
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
        "27d6a5ee4d822a94f5455edd439da83e9fb5c37ac914b677fee1128d8c9b074a"))
    sender = LocalAccount(private_key)
    transfer(sender, "22cad4c80415fd0d56f8652785fcda35", 4, 100_00_00)
