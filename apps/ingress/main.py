import asyncio

TARGETS = {8080: "vulnerable", 8081: "hardened", 8082: "control"}
LIMIT = asyncio.Semaphore(64)


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target: str) -> None:
    if LIMIT.locked():
        writer.close()
        await writer.wait_closed()
        return
    async with LIMIT:
        upstream_writer = None
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(target, 8080),
                timeout=3,
            )

            async def pump(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
                while chunk := await asyncio.wait_for(source.read(65536), timeout=30):
                    destination.write(chunk)
                    await asyncio.wait_for(destination.drain(), timeout=5)

            tasks = [
                asyncio.create_task(pump(reader, upstream_writer)),
                asyncio.create_task(pump(upstream_reader, writer)),
            ]
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        except (OSError, TimeoutError):
            pass
        finally:
            if upstream_writer:
                upstream_writer.close()
                await upstream_writer.wait_closed()
            writer.close()
            await writer.wait_closed()


async def main() -> None:
    servers = []
    for port, target in TARGETS.items():
        # The listener chooses one of three constant destinations. Raw request data
        # can never select a host, port, URL, CONNECT tunnel, or forwarding route.
        async def handle(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter, destination: str = target
        ) -> None:
            await relay(reader, writer, destination)

        servers.append(await asyncio.start_server(handle, "0.0.0.0", port))  # noqa: S104  # nosec B104
    await asyncio.gather(*(server.serve_forever() for server in servers))


if __name__ == "__main__":
    asyncio.run(main())
