from starcoin.sdk.local_account import LocalAccount
if __name__ == "__main__":
    account = LocalAccount.generate()
    private_key = account.private_key_hex
    account1 = LocalAccount.from_private_key(private_key)
    assert private_key == account1.private_key_hex
