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
    def __init__(
            self,
            url,
    ):
        self.request = RpcRequest(url)
        self.session = Session()

    def node_info(self,) -> dict:
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

    def state_get(self, access_path: starcoin_types.AccessPath) -> bytes:
        operation = {
            "rpc_method": "state_hex.get",
            "params": [access_path.lcs_serialize().hex()]
        }
        ret = self.__execute(operation)
        if ret is None:
            raise StateNotFoundError("State not found")
        return ret

    def get_account_token(self, addr: typing.Union[starcoin_types.AccountAddress, bytes, str], module: str, name: str) -> int:
        account_address = utils.account_address(addr)
        struct_tag = starcoin_types.StructTag(
            address=utils.account_address(utils.CORE_CODE_ADDRESS),
            module=starcoin_types.Identifier("Account"),
            name=starcoin_types.Identifier("Balance"),
            type_params=[starcoin_types.TypeTag__Struct(starcoin_types.StructTag(
                address=utils.account_address(utils.CORE_CODE_ADDRESS),
                module=starcoin_types.Identifier(module),
                name=starcoin_types.Identifier(name),
                type_params=[]))],
        )
        struct_tag_hash = utils.hash(utils.starcoin_hash_seed(
            b"StructTag"), struct_tag.lcs_serialize())
        path = []
        path.append(utils.RESOURCE_TAG)
        path.extend(struct_tag_hash)
        access_path = starcoin_types.AccessPath(
            address=account_address, path=bytes(path))
        state = self.state_get(access_path)
        balance = starcoin_types.BalanceResource.lcs_deserialize(state)
        return int(balance.token)

    def get_account_sequence(self, addr: typing.Union[starcoin_types.AccountAddress, bytes, str]) -> int:
        account_address = utils.account_address(addr)
        struct_tag = starcoin_types.StructTag(
            address=utils.account_address(utils.CORE_CODE_ADDRESS),
            module=starcoin_types.Identifier("Account"),
            name=starcoin_types.Identifier("Account"),
            type_params=[],
        )
        struct_tag_hash = utils.hash(utils.starcoin_hash_seed(
            b"StructTag"), struct_tag.lcs_serialize())
        path = []
        path.append(utils.RESOURCE_TAG)
        path.extend(struct_tag_hash)
        access_path = starcoin_types.AccessPath(
            address=account_address, path=bytes(path))
        state = self.state_get(access_path)
        account_resource = starcoin_types.AccountResource.lcs_deserialize(
            state)
        return int(account_resource.sequence_number)

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
