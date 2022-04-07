from starcoin.starcoin_types import *
from starcoin.sdk import utils, client, local_account
from starcoin.starcoin_stdlib import encode_accept_token_script_function
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from starcoin import bcs


def send_txn(cli, sender, script_funtion):
    node_info = cli.node_info()
    now_seconds = int(node_info.get('now_seconds'))
    # expired after 12 hours
    expiration_timestamp_secs = now_seconds + 43200
    seq_num = cli.get_account_sequence(
        "0x"+sender.account_address.bcs_serialize().hex())
    raw_txn = RawUserTransaction(
        sender=sender.account_address,
        sequence_number=seq_num,
        payload=script_funtion,
        max_gas_amount=10000000,
        gas_unit_price=1,
        gas_token_code="0x1::STC::STC",
        expiration_timestamp_secs=expiration_timestamp_secs,
        chain_id=ChainId(st.uint8(251)),
    )

    txn = sender.sign(raw_txn)
    print(cli.submit(txn))


if __name__ == "__main__":
    cli = client.Client("http://barnard.seed.starcoin.org:9850")
    # sender
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
        "e424e16db235e3f3b9ef2475516c51d4c15aa5287ceb364213698bd551eab4f2"))
    sender = local_account.LocalAccount(private_key)
    token = utils.currency_user_code(
        "07fa08a855753f0ff7292fdcbe871216", "Usdx")
    #script_funtion = encode_accept_token_script_function(token)
    #build_tx(cli, sender, script_funtion)
    script_funtion = TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "07fa08a855753f0ff7292fdcbe871216"), name=Identifier("TokenSwapScripts")),
            function=Identifier("swap_token_for_exact_token"),
            ty_args=[utils.currency_code("STC"), token],
            args=[bcs.serialize(630, st.uint128),
                  bcs.serialize(60, st.uint128)],
        )
    )
    send_txn(cli, sender, script_funtion)
