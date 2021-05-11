from starcoin.sdk.receipt_identifier import ReceiptIdentifier
from starcoin.starcoin_types import AccountAddress
from starcoin.sdk.auth_key import AuthKey
from starcoin.sdk import utils


def test_receipt_identifier():
    auth_key_hex = "93dcc435cfca2dcf3bf44e9948f1f6a98e66a1f1b114a4b8a37ea16e12beeb6d"
    address_hex = "1603d10ce8649663e4e5a757a8681833"

    # encode
    receipt = ReceiptIdentifier(
        AccountAddress.from_hex(address_hex), AuthKey(bytes.fromhex(auth_key_hex))).encode()
    # deocode
    decode_receipt = ReceiptIdentifier.decode(receipt)

    assert utils.account_address_hex(
        decode_receipt.account_address) == address_hex
    assert decode_receipt.auth_key.hex() == auth_key_hex
