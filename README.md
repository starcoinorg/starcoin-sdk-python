# starcoin-sdk-python
## Document

The document of starcoin sdk for python: [documents site](https://starcoin-sdk-python.readthedocs.io/en/latest/).

## Pypi package

https://pypi.org/project/starcoin-sdk-python/

## Usage
``` python
from starcoin import starcoin_types as types
from starcoin import starcoin_stdlib as stdlib
from starcoin import serde_types as st
from starcoin.sdk import (utils, client, local_account, auth_key)
from starcoin.sdk.receipt_identifier import ReceiptIdentifier
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
	
# create a client for connecting starcoin node
cli = client.Client("https://barnard-seed.starcoin.org")

# get the node info
print(cli.node_info())

# get the resource of account
account_resource = cli.state_get(
        '0x00000000000000000000000000000001/1/0x00000000000000000000000000000001::Account::Account')
print(account_resource)

# create a account with your private key
private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
"e424e16db235e3f3b9ef2475516c51d4c15aa5287ceb364213698bd551eab4f2"))
account = local_account.LocalAccount(private_key)

# define a transfer function
def transfer(cli: client.Client, sender: local_account.LocalAccount, receipt: str, amount: st.uint128):
    seq_num = cli.get_account_sequence(
        "0x"+sender.account_address.bcs_serialize().hex())
    receipt = ReceiptIdentifier.decode(receipt)
    script = stdlib.encode_peer_to_peer_v2_script_function(
        token_type=utils.currency_code("STC"),
        payee=receipt.account_address,
        amount=amount,
    )
    node_info = cli.node_info()
    now_seconds = int(node_info.get('now_seconds'))
    # expired after 12 hours
    expiration_timestamp_secs = now_seconds + 43200
    raw_txn = types.RawUserTransaction(
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

```

More examples see [examples](https://github.com/starcoinorg/starcoin-sdk-python/tree/master/examples)
