# ADR 0003: Fixed ingress relay, internal application runtimes

Status: accepted after measured full-stack testing.

The first full-stack hosted execution proved that services were healthy internally and ZAP could reach hardened HarborDesk, while the host could not connect to the published loopback application ports. An internal-only application network was insufficient for reliable host publication in that Docker configuration.

The solution preserves internal networks for every application/database and publishes the three loopback ports only through a small standard-library TCP relay. It has three listeners with constant destinations: vulnerable:8080, hardened:8080 and control:8080. Request bytes, Host headers, paths, absolute URLs and CONNECT text never choose another destination. The relay does not implement IP routing and explicitly disables kernel forwarding. Only it joins the dedicated ingress bridge; the vulnerable runtime still has no egress-capable network.

This adds one trusted intermediary and makes its role explicit in configuration validation. The guard checks exact port mappings/network membership, including the sole permitted non-internal network, and rejects enabling forwarding or attaching the vulnerable app to that network. A real TCP regression proves that destination-looking request bytes do not alter the fixed upstream. Hosted loopback/browser checks remain necessary to verify the composed behavior.

The relay runs non-root/read-only with all capabilities dropped, and accepts at most 64 concurrent connections with bounded idle/drain/connect timeouts. Compromise of this intermediary remains a residual risk; no general proxy, shell execution, Docker access or host mount is provided.

Docker's [port-publishing](https://docs.docker.com/engine/network/port-publishing/) and [bridge](https://docs.docker.com/engine/network/drivers/bridge/) documentation explain the distinction between internal connectivity, gateway behavior and host publication. Effective tests, rather than the presence of a `ports` field alone, determine acceptance.
