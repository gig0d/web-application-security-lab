# ADR 0004: Enforce a supported Docker loopback boundary

Status: accepted.

Docker documents that releases before Engine 28 can expose localhost-published ports to machines on the same layer-2 segment. A loopback-only YAML address alone therefore cannot establish this project's isolation requirement on those releases.

Host lifecycle operations require Engine 28 or later and a local Unix socket or Windows named pipe. Unsupported/unknown versions and remote daemon endpoints fail closed. This is checked before starting, resetting or scanning containers. It does not change host daemon configuration or firewall rules.

See the official [port-publishing warning](https://docs.docker.com/engine/network/port-publishing/). Host/daemon compromise and deliberate direct-routing changes remain outside the application's trust boundary.
