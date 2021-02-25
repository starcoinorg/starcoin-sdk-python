# Copyright (c) The starcoin Core Contributors

from requests import Session, Request
from starcoin import starcoin_types
from . import utils
import typing


class InvalidServerResponse(Exception):
    pass


class StateNotFoundError(ValueError):
    pass


class JsonResponseError(Exception):
    pass


class Client():
    """Starcoin sdk client
    """

    def __init__(
            self,
            url,
    ):
        self.request = RpcRequest(url)
        self.session = Session()

    def node_info(self,) -> dict:
        """Starcoin node information

        Return the node information
        """
        operation = {
            "rpc_method": "node.info",
            "params": None,
        }
        return self.__execute(operation)

    def node_status(self,) -> bool:
        operation = {
            "rpc_method": "node.status",
            "params": None,
        }
        ret = self.__execute(operation)
        return ret

    def get_transaction(self, txn_hash: str) -> dict:
        operation = {
            "rpc_method": "chain.get_transaction",
            "params": [txn_hash],
        }
        ret = self.__execute(operation)
        return ret

    def get_block_by_number(self, number: int) -> dict:
        operation = {
            "rpc_method": "chain.get_block_by_number",
            "params": [number],
        }
        ret = self.__execute(operation)
        return ret

    def submit(self, txn: typing.Union[starcoin_types.SignedUserTransaction, str]):
        if isinstance(txn, starcoin_types.SignedUserTransaction):
            return self.submit(txn.lcs_serialize().hex())

        operation = {
            "rpc_method": "txpool.submit_hex_transaction",
            "params": [txn]
        }
        return self.__execute(operation)

    def state_get(self, access_path: str) -> bytes:
        operation = {
            "rpc_method": "state.get",
            "params": [access_path]
        }
        ret = self.__execute(operation)
        if ret is None:
            raise StateNotFoundError("State not found")
        return ret

    def is_account_exist(self, addr: str) -> bool:
        try:
            self.get_account_resource(addr)
        except StateNotFoundError:
            return False
        return True

    def get_account_sequence(self, addr: str) -> int:
        try:
            account_resource = self.get_account_resource(addr)
        except StateNotFoundError:
            return 0
        return int(account_resource.sequence_number)

    def get_account_token(self, addr: str, module: str, name: str) -> int:
        type_parm = "{}::{}::{}".format(utils.CORE_CODE_ADDRESS, module, name)

        struct_tag = "{}::{}::{}<{}>".format(utils.CORE_CODE_ADDRESS,
                                             "Account", "Balance", type_parm)
        path = "{}/{}/{}".format(addr,
                                 utils.RESOURCE_TAG, struct_tag)
        state = self.state_get(path)
        balance = starcoin_types.BalanceResource.lcs_deserialize(state)
        return int(balance.token)

    def get_account_resource(self, addr: str) -> starcoin_types.AccountResource:
        struct_tag = "{}::{}::{}".format(
            utils.CORE_CODE_ADDRESS, "Account", "Account")
        path = "{}/{}/{}".format(addr, utils.RESOURCE_TAG, struct_tag)
        state = self.state_get(path)
        account_resource = starcoin_types.AccountResource.lcs_deserialize(
            state)
        return account_resource

    def sign_txn(self, raw_txn, signer):
        pass

    # todo: error code handle

    def __execute(self, operation) -> str:
        req = self.request.prepare(
            rpc_method=operation["rpc_method"], params=operation["params"])
        resp = self.session.send(req)
        resp.raise_for_status()
        try:
            json = resp.json()
        except ValueError as e:
            raise InvalidServerResponse(
                f"Parse response as json failed: {e}, response: {resp.text}")
        if json.get("error") is not None:
            raise JsonResponseError(f"Response:{resp.text}")
        return json.get("result")


class RpcRequest():
    def __init__(self, url):
        self.setting = {
            "url": url,
            "method": "POST",
            "request_id": "sdk-client",
            "headers": {"Content-type": "application/json"},
        }

    def prepare(self, rpc_method, params=None):
        method = self.setting["method"]
        url = self.setting["url"]
        post_data = {
            "jsonrpc": "2.0",
            "id": self.setting["request_id"],
            "method": rpc_method,
            "params": params,
        }
        headers = self.setting["headers"]
        req = Request(method=method, url=url, json=post_data, headers=headers)
        return req.prepare()
