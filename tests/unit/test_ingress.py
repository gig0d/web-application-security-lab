import asyncio

from apps.ingress.main import TARGETS, relay


def test_relay_carries_response_only_to_its_fixed_upstream(monkeypatch):
    async def scenario():
        async def upstream(reader, writer):
            data = await reader.readuntil(b"\r\n\r\n")
            assert b"CONNECT arbitrary.example" in data  # Bytes cannot choose a destination.
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nsafe")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        upstream_server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        upstream_port = upstream_server.sockets[0].getsockname()[1]
        original = asyncio.open_connection
        destinations = []

        async def fixed(host, port):
            destinations.append((host, port))
            assert (host, port) == ("hardened", 8080)
            return await original("127.0.0.1", upstream_port)

        monkeypatch.setattr(asyncio, "open_connection", fixed)
        gateway = await asyncio.start_server(lambda r, w: relay(r, w, "hardened"), "127.0.0.1", 0)
        try:
            reader, writer = await original("127.0.0.1", gateway.sockets[0].getsockname()[1])
            writer.write(b"CONNECT arbitrary.example HTTP/1.1\r\nHost: arbitrary.example\r\n\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), 3)
            assert response.endswith(b"safe")
            assert destinations == [("hardened", 8080)]
            writer.close()
            await writer.wait_closed()
        finally:
            gateway.close()
            upstream_server.close()
            await gateway.wait_closed()
            await upstream_server.wait_closed()

    asyncio.run(scenario())
    assert TARGETS == {8080: "vulnerable", 8081: "hardened", 8082: "control"}
