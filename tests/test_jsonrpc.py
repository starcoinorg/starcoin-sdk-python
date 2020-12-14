from sdk import client
cli = client.Client("http://proxima1.seed.starcoin.org:9850")


def test_node_api():
    status = cli.node_status()
    assert status is True
    assert cli.node_info().get("net") == "proxima"


def test_chain_api():
    cli.get_transaction(
        "0x6c52e4fee383b938f4ccb50e575b416c1596257b6c1e85ede80cde7584aec9c9")
    cli.get_block_by_number(1)
