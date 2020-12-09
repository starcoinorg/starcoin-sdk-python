from client import Client
import logging


def init_logger(log_level):
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(log_level)
    requests_log.propagate = True


if __name__ == "__main__":
    init_logger(logging.DEBUG)
    client = Client("http://sanlee1:9850")
    resp = client.node_status()
    print(resp)
