# Contributing

Read `AGENTS.md` before changing this repository. All contributions, documentation and UI text use professional English. Preserve synthetic-only data, loopback publication, fixed scanner scope and separate application images. Do not introduce a global vulnerability switch or a public deployment path.

For a change, identify the legitimate business workflow, threat boundary and lab affected. Add an assertion for the unintended action and a legitimate-use assertion; place expected vulnerable behavior only in the explicitly selected training suite. Browser execution claims need a real Playwright check. PostgreSQL claims need actual PostgreSQL evidence. Keep docs and the catalog aligned with source.

```powershell
python -m pip install --require-hashes -r requirements-dev.lock
python -m ruff format apps scripts tests infrastructure/database/migrations
python -m ruff check apps scripts tests
python -m mypy apps scripts
python -m pytest
python -m pytest tests/training
python -m scripts.isolation
python -m scripts.zap_scope
```

Run browser, Docker, PostgreSQL, Bandit and advisory checks as appropriate to the change. Document skipped/unavailable checks. Never create success fixtures, copied scanner results or fabricated screenshots to satisfy acceptance. `python -m scripts.documentation --check` checks generated lab guides and mappings against their source catalog.

Project development commits must use the exact author and committer identity in `AGENTS.md`, cohesive Conventional Commits, post-commit identity verification and verified pushes. Never rewrite unrelated history, force push or add automation attribution. Do not enable automated bot-authored development commits. Any external contribution process requires an owner-approved policy before work is accepted.

Pull request descriptions should explain the concrete failure, resulting behavior, security boundary, relevant evidence and remaining limitations. Changes to Compose, scan scope, reset resources or vulnerable/hardened separation deserve explicit review. This repository's workflows have read-only permissions and never publish application images.
