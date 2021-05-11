from starcoin.sdk.auth_key import AuthKey
from starcoin.starcoin_types import AccountAddress
from typing import Union
from starcoin.sdk import bech32
from starcoin.sdk import utils


class ReceiptIdentifier:
    """
    ref: [sip-21](https://github.com/starcoinorg/SIPs/blob/master/sip-21/index.md)
    """
    account_address: AccountAddress
    auth_key: Union[AuthKey, None]

    def __init__(self, account_address: AccountAddress,
                 auth_key: Union[AuthKey, None]):
        self.account_address = account_address
        self.auth_key = auth_key

    def encode(self) -> "str":
        data = bytearray(self.account_address.bcs_serialize())
        if isinstance(self.auth_key, AuthKey):
            data.extend(bytearray(self.auth_key.data))
        return bech32.encode("stc", 1, data)

    @staticmethod
    def decode(s: str) -> "ReceiptIdentifier":
        (version, data) = bech32.decode("stc", s)
        if version != 1:
            return None
        address = AccountAddress.from_hex(
            bytearray(data[0:utils.ACCOUNT_ADDRESS_LEN]).hex())
        if len(data) == utils.ACCOUNT_ADDRESS_LEN:
            auth_key = None
        else:
            auth_key = AuthKey(bytes(data[utils.ACCOUNT_ADDRESS_LEN:]))

        return ReceiptIdentifier(address, auth_key)
