# Network and container isolation

Only three host publications are permitted: `127.0.0.1:18080:8080`, `127.0.0.1:18081:8080`, and `127.0.0.1:18082:8080`. Databases, simulator and scanner expose no host ports. Uvicorn listens on the container's own interface; Docker's explicit loopback publication controls host exposure. Never replace that host binding with `0.0.0.0`, an omitted host address or an external interface.

`vulnerable-net`, `hardened-net` and `control-net` are project-owned internal networks. The databases belong only to their matching application network. The control center and fixed simulator join both application networks for comparison/preview operations; neither implements an arbitrary proxy, packet forwarding or a URL fetch API. The scanner joins only the hardened network and starts only under its explicit profile. None of the runtime services joins the default external bridge.

All application/control/simulator containers run as UID/GID 10001 with a read-only root filesystem. PostgreSQL runs as UID/GID 999 with only its data volume writable. ZAP uses UID/GID 1000, a disposable report mount and temporary directories. Capabilities are dropped, privilege escalation is disabled, and process, CPU and memory limits are configured. No Docker socket, host networking, device mount, real host document directory or external volume is permitted.

## Validate before and after startup

```powershell
python -m scripts.isolation
python -m scripts.lab init
python -m scripts.isolation --resolved
python -m scripts.lab up
python -m scripts.lab inspect
```

Source validation rejects unsafe ports, privileged/root execution, missing limits, unapproved service/network membership and host/data mounts. Resolved validation inspects Compose's interpolated JSON in memory and suppresses credentials in output. Effective inspection checks actual container publication, users, dropped capabilities and network membership and confirms that the actual networks are internal. Startup stops the project if post-start inspection fails.

Unit tests mutate the approved manifest into unsafe examples and assert rejection. These tests establish validator behavior; they are not evidence of a running Docker network. A hardened-only CI startup uses `python -m scripts.isolation --resolved --runtime --scope hardened` and still checks every existing project container rather than ignoring other services.

The lifecycle CLI rejects nonlocal Docker contexts (`tcp://`, SSH or other remote endpoints), accepts no custom project/file/target paths and never calls a shell. Do not bypass it using Compose overrides, externally managed networks or a forwarded daemon. Bind mounts are limited to the database initializer, scanner plans and scanner report directory. Named volumes must retain their exact Aegis names and ownership.

## Verification limits

An internal network flag is a control configuration, not a packet-capture result. Verify the effective configuration on the actual Docker Desktop version before accepting containment. Container networking on Windows depends on Docker's Linux VM; firewall, VPN and daemon changes can alter behavior. A hostile host administrator or a compromised Docker daemon is outside this lab's threat boundary. Loopback services are accessible to local processes, and local HTTP does not provide TLS confidentiality.

Do not test egress by contacting a public address or real cloud metadata. Inspect effective routes/network flags and use only repository-owned internal fixtures for any connectivity experiment. There is no cloud/public deployment procedure for the vulnerable application.
