"""Generate precise lab guides and mapping table from the shared verified catalog."""

import argparse
import ast
import re
from pathlib import Path

from apps.lab_control.catalog import LABS, ROOT

METHODS = [
    "ticket",
    "attachment",
    "admin",
    "search",
    "render",
    "render",
    "csrf",
    "login_error",
    "revoke",
    "upload",
    "preview",
    "error",
]


def method_source(filename: str, class_name: str, name: str) -> str:
    source = (ROOT / filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for method in node.body:
                if (
                    isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and method.name == name
                ):
                    return ast.get_source_segment(source, method) or ""
    raise ValueError(f"Expected implemented method missing: {name}")


def outputs() -> dict[Path, str]:
    result = {}
    for lab, method in zip(LABS, METHODS, strict=True):
        unsafe = method_source("apps/vulnerable/policy.py", "TrainingPolicy", method)
        safe = method_source("apps/core/security.py", "SecurePolicy", method)
        content = [
            f"# Lab {lab.number} — {lab.name}",
            f"{lab.difficulty} · {lab.category} · {lab.cwe}",
            "## Legitimate business workflow",
            lab.scenario,
            lab.objective,
            "## Authorized scope and preconditions",
            "Only the repository-created local HarborDesk pair is authorized: vulnerable at http://127.0.0.1:18080 and hardened at http://127.0.0.1:18081. Use the fictional accounts documented in the README. Default actor is Alice unless a step names another account. Do not substitute external targets, real data or executable uploads.",
            "## Reproduce and collect evidence",
            *[f"{i}. {step}" for i, step in enumerate(lab.steps, 1)],
            "## Expected comparison",
            lab.expected,
            "Record actual status codes, returned identifiers, state changes or browser markers. An expected result is not evidence until the corresponding action executes. The control center records bounded HTTP checks; the browser suite records real browser behavior. Consult the verification record for what has actually run.",
            "## Underlying weakness",
            lab.root_cause,
            "The implemented training override is:",
            "```python\n" + unsafe + "\n```",
            "## Hardened implementation",
            lab.remediation,
            "The corresponding secure policy is:",
            "```python\n" + safe + "\n```",
            f"Shared business route: `{lab.component}`.",
            "## Automated remediation verification",
            f"Named test: `{lab.test}`.",
            "```powershell\npython -m pytest tests/training -k " + lab.id + "\n```"
            if lab.id not in {"lab05", "lab06"}
            else "```powershell\npython -m pytest tests/browser\n```",
            "The full training suite includes a vulnerable observation, corresponding hardened assertion and legitimate-use checks. Labs 01, 05, 06 and 07 also have Playwright evidence. SQLite/controlled-transport evidence does not establish PostgreSQL/network behavior. Run the relevant complete suite when changing shared controls.",
            "## Restore a known state",
            "Use the control center's confirmed synthetic-business-data reset, then sign in again. For a complete database-volume reset run `python -m scripts.lab reset` from the repository; only the two named Aegis business volumes are replaced. Learning notes/evidence survive. For deterministic tests, fresh disposable fixtures are created automatically. Never use broad host or Docker cleanup commands.",
            "## Risk mappings and references",
            lab.owasp,
            "ASVS 5.0.0 selected requirements: " + ", ".join(lab.asvs) + ".",
            "WSTG 4.2 reference: " + lab.wstg + ".",
            "These are selected contextual mappings, not a complete category or ASVS-compliance claim. Severity is qualitative fictional impact; no CVSS score is fabricated.",
            "- [OWASP Top 10:2025](https://top10.owasp.org/2025/)\n- [ASVS 5.0.0 release](https://github.com/OWASP/ASVS/tree/v5.0.0)\n- [WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)\n- [Secure policy source](../../apps/core/security.py)\n- [Intentional training policy](../../apps/vulnerable/policy.py)",
            "## Limits and secure-development lesson",
            lab.residual,
            lab.remediation
            + " Verify the effect at the affected trust boundary and preserve the legitimate workflow; configuring a control is not the same as proving it works.",
        ]
        result[ROOT / "labs" / lab.id / "README.md"] = "\n\n".join(content) + "\n"
    rows = [
        "# OWASP and CWE mapping",
        "",
        "Mappings are selected educational references. They do not assert complete coverage or ASVS certification. ASVS identifiers were checked against the official pinned v5.0.0 CSV, not the moving development branch. WSTG identifiers explicitly use v42.",
        "",
        "| Lab | CWE | OWASP Top 10:2025 | ASVS 5.0.0 | WSTG 4.2 |",
        "| --- | --- | --- | --- | --- |",
    ]
    rows += [
        f"| {lab.number}: {lab.name} | {lab.cwe} | {lab.owasp} | {', '.join(lab.asvs)} | {lab.wstg} |"
        for lab in LABS
    ]
    rows += [
        "",
        "Top 10:2025 awareness also informs dependency integrity, cryptography and logging controls. A03 software supply-chain failures, A04 cryptographic failures, A06 insecure design, A08 integrity failures and A09 logging/alerting failures are not claimed as complete additional laboratory coverage. CSRF and SSRF are contextual broken-access-control mappings; file-upload scenario mapping reflects its configured acceptance boundary rather than an exhaustive official CWE crosswalk.",
        "",
        "ASVS 8.2.2 concerns data-specific permission, 8.2.1 function permission, 1.2.4 database parameterization, 1.2.1 output context, 3.5.1 request forgery, 6.3.1/6.3.8 login defenses, 7.4.1 termination, 5.2/5.3 file validation/storage, 1.3.6 SSRF and 16.5.1 safe errors. The lab implements and tests selected portions only. Default public fixture accounts and loopback HTTP deliberately prevent a general compliance claim.",
        "",
        "Sources: [Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/), [pinned ASVS CSV](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv), [WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/).",
        "",
    ]
    result[ROOT / "docs/owasp-mapping.md"] = "\n".join(rows)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    mismatches = []
    for path, content in outputs().items():
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                mismatches.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
    if mismatches:
        raise SystemExit("Regenerate documentation: " + ", ".join(mismatches))
    if args.check:
        markdown_files = [
            ROOT / name for name in ("README.md", "AGENTS.md", "SECURITY.md", "CONTRIBUTING.md")
        ]
        markdown_files += list((ROOT / "docs").rglob("*.md"))
        markdown_files += list((ROOT / "labs").rglob("*.md"))
        for path in markdown_files:
            for link in re.findall(r"\[[^\]]+\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
                if link.startswith(("http://", "https://", "#")):
                    continue
                target = link.split("#", 1)[0]
                if target and not (path.parent / target).exists():
                    raise SystemExit(f"Broken local documentation link in {path.name}: {target}")
    print("Lab documentation " + ("checked" if args.check else "generated"))


if __name__ == "__main__":
    main()
