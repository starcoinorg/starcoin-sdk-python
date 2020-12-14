from starcoin import starcoin_types as types
from starcoin import starcoin_stdlib as stdlib
from starcoin import serde_types as st
from starcoin.sdk import (utils, client, local_account)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import time


def transfer(cli: client.Client, sender: local_account.LocalAccount, payee: str, amount: st.uint128):
    seq_num = cli.get_account_sequence(sender.account_address)
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
    print(cli.submit(txn))


if __name__ == "__main__":
    cli = client.Client("http://sanlee1:9850")
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
        "27d6a5ee4d822a94f5455edd439da83e9fb5c37ac914b677fee1128d8c9b074a"))
    sender = local_account.LocalAccount(private_key)
    transfer(cli, sender, "0x22cad4c80415fd0d56f8652785fcda35", 100_00_00)
    print(cli.get_account_token("0x22cad4c80415fd0d56f8652785fcda35", "STC", "STC"))
