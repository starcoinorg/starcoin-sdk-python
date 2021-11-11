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

    def execute(self, operation):
        """ Execute a rpc request operation
        operation = {
            "rpc_method": $rpc_method,
            "params": $params,
        }
        such as:
        operation = {
            "rpc_method": "node.info",
            "params": None,
        }

        """
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

    def node_info(self,) -> dict:
        """Starcoin node information

        Return the node information
        """
        operation = {
            "rpc_method": "node.info",
            "params": None,
        }
        return self.execute(operation)

    def node_status(self,) -> bool:
        """ Starcoin node status

        """
        operation = {
            "rpc_method": "node.status",
            "params": None,
        }
        ret = self.execute(operation)
        return ret

    def get_transaction(self, txn_hash: str) -> dict:
        operation = {
            "rpc_method": "chain.get_transaction",
            "params": [txn_hash],
        }
        ret = self.execute(operation)
        return ret

    def get_transaction_info(self, txn_hash: str) -> dict:
        operation = {
            "rpc_method": "chain.get_transaction_info",
            "params": [txn_hash],
        }
        ret = self.execute(operation)
        return ret

    def get_blocks_by_number(self, number: int, count: int) -> dict:
        operation = {
            "rpc_method": "chain.get_blocks_by_number",
            "params": [number, count],
        }
        ret = self.execute(operation)
        return ret

    def get_block_by_number(self, number: int) -> dict:
        operation = {
            "rpc_method": "chain.get_block_by_number",
            "params": [number],
        }
        ret = self.execute(operation)
        return ret

    def submit(self, txn: typing.Union[starcoin_types.SignedUserTransaction, str]):
        if isinstance(txn, starcoin_types.SignedUserTransaction):
            return self.submit(txn.bcs_serialize().hex())

        operation = {
            "rpc_method": "txpool.submit_hex_transaction",
            "params": [txn]
        }
        return self.execute(operation)

    def state_get(self, access_path: str) -> bytes:
        operation = {
            "rpc_method": "state.get",
            "params": [access_path]
        }
        ret = self.execute(operation)
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
        balance = starcoin_types.BalanceResource.bcs_deserialize(bytes(state))
        return int(balance.token)

    def get_account_resource(self, addr: str) -> starcoin_types.AccountResource:
        struct_tag = "{}::{}::{}".format(
            utils.CORE_CODE_ADDRESS, "Account", "Account")
        path = "{}/{}/{}".format(addr, utils.RESOURCE_TAG, struct_tag)
        state = self.state_get(path)
        account_resource = starcoin_types.AccountResource.bcs_deserialize(
            bytes(state))
        return account_resource

    def get_resource(self, addr: str, resource_type: str, option=None):
        operation = {
            "rpc_method": "state.get_resource",
            "params": [addr, resource_type, option],
        }
        return self.execute(operation)

    def get_block_events(self, filter, option=None):
        '''
        filter: {'from_block':2, 'to_block':5, 'event_keys':[], 'addrs':[], 'type_tags':[], 'limit': None}
        option: {'decode':true}
        '''
        operation = {
            u"rpc_method": u"chain.get_events",
            u"params": [filter, option],
        }
        return self.execute(operation)

    def get_state_root_by_height(self, block_number: int):
        operation = {
            u"rpc_method": u"chain.get_block_by_number",
            u"params": [block_number],
        }
        state_root = self.execute(operation).get("header").get("state_root")
        return state_root

    def get_block_reward(self, block_number: int):
        u""" get block reward by blcok_number, block_number shoule less than header.block_number
        return coin_reward, author, gas_fee
        """
        operation = {
            u"rpc_method": u"chain.get_block_by_number",
            u"params": [block_number+1],
        }
        state_root = self.execute(operation).get("header").get("state_root")
        operation = {
            u"rpc_method": u"state.get_account_state_set",
            u"params": ["0x1", state_root],
        }
        state_set = self.execute(operation)
        infos = state_set.get("resources").get(
            "0x00000000000000000000000000000001::BlockReward::RewardQueue").get(
                "value")[1][1].get("Vector")
        for info in infos:
            info = info.get("Struct").get("value")
            if int(info[0][1].get("U64")) != block_number:
                continue
            reward = int(info[1][1].get("U128"))
            author = info[2][1].get("Address")
            gas_fee = int(info[3][1].get("Struct").get(
                "value")[0][1].get("U128"))
        return (reward, author, gas_fee)

    def get_events_by_txn_hash(self, txn_hash: str):
        operation = {
            "rpc_method": "chain.get_events_by_txn_hash",
            "params": [txn_hash],
        }
        ret = self.execute(operation)
        return ret

    def get_txpool_pending_txn(self, txn_hash: str) -> dict:
        operation = {
            "rpc_method": "txpool.pending_txn",
            "params": [txn_hash],
        }
        ret = self.execute(operation)
        return ret

    def contract_call(self, function_id: str, type_args: list, args: list):
        operation = {
            "rpc_method": "contract.call_v2",
            "params": [{
                "function_id": function_id,
                "type_args": type_args,
                "args": args,
            }],
        }
        ret = self.execute(operation)
        return ret


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
