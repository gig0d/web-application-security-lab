# ADR 0001: Separate images and explicit security policies

Status: accepted.

HarborDesk shares relational business models and templates, but uses distinct entry points and policy modules for vulnerable and hardened behavior. The hardened container copies only the shared core and hardened policy; it cannot import the vulnerable package. An environment flag cannot select the unsafe implementation.

Each application uses a separate PostgreSQL service and private internal Docker network. An internal preview simulator returns synthetic information. The lab control center has its own persistence and cannot invoke Docker or accept shell commands. Reset is a host-side command limited to an exact service/project allowlist. Loopback-only published ports allow interactive local learning. Internal networks block Internet egress; source and runtime inspections enforce complementary checks.

Tradeoffs: deliberate business-layer duplication is avoided, while policy differences remain reviewable. The vulnerable image still contains intentionally unsafe operations and must never become a production image. Local HTTP cannot provide end-to-end transport security; the hardened lab documents its loopback cookie exception and supports secure cookies when TLS is supplied. SQLite tests accelerate development but cannot establish PostgreSQL correctness.
