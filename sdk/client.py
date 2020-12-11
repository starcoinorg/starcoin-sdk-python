from requests import Session, Request
import starcoin_types
import typing


class InvalidServerResponse(Exception):
    pass


class Client():
    def __init__(
            self,
            url,
    ):
        self.request = RpcRequest(url)
        self.session = Session()

    def node_info(self,):
        operation = {
            "rpc_method": "node.info",
            "params": None,
        }
        return self.__execute(operation)

    def node_status(self,):
        operation = {
            "rpc_method": "node.status",
            "params": None,
        }
        return self.__execute(operation)

    def submit(self, txn: typing.Union[starcoin_types.SignedUserTransaction, str]):
        if isinstance(txn, starcoin_types.SignedUserTransaction):
            return self.submit(txn.lcs_serialize().hex())

        operation = {
            "rpc_method": "txpool.submit_hex_transaction",
            "params": [txn]
        }
        return self.__execute(operation)

    def __execute(self, operation):
        req = self.request.prepare(
            rpc_method=operation["rpc_method"], params=operation["params"])
        resp = self.session.send(req)
        resp.raise_for_status()
        try:
            json = resp.json()
        except ValueError as e:
            raise InvalidServerResponse(
                f"Parse response as json failed: {e}, response: {resp.text}")
        return json


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
