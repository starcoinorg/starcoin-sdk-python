from sdk import client

def test_node_info():
    cli = client.Client("http://sanlee1:9850")
    resp = cli.node_status()
