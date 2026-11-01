# Aegis engineering contract

Owner: Giovanny Alvarado Barrantes. Repository: `gig0d/web-application-security-lab`.
All code, documentation, tests, UI text, commit messages, and technical explanations use professional English.

## Mandatory Git authorship policy

Every new project commit must show exactly:

Author: Giovanny Alvarado Barrantes <gioab0411@gmail.com>

Committer: Giovanny Alvarado Barrantes <gioab0411@gmail.com>

GitHub username: `gig0d`.
Expected origin: `https://github.com/gig0d/web-application-security-lab.git`.

Before the first commit in a session:

1. Inspect the workspace and existing Git state; preserve unrelated work.
2. Confirm this repository, current branch, and every remote.
3. Verify `origin` points to the exact expected repository.
4. Set repository-local identity with `git config --local user.name "Giovanny Alvarado Barrantes"` and `git config --local user.email "gioab0411@gmail.com"`.
5. Inspect environment variables and configuration that might override author or committer identity. Do not print credentials.
6. Verify BOTH effective identities with `git var GIT_AUTHOR_IDENT` and `git var GIT_COMMITTER_IDENT`; correct conflicts before committing.

Never use Codex, OpenAI, another AI system, or an automation bot as author or committer for project development commits. Never add AI `Co-authored-by` trailers, attribution, signatures, or promotional credits to commit messages or repository credits. Retain third-party license notices and legally required attribution. Do not falsify timestamps or rewrite history to conceal changes.

Use cohesive Conventional Commits after completed, tested milestones. Verify BOTH author and committer after EVERY commit (`git show -s --format=fuller HEAD`). Push completed commits to the authorized origin and verify the remote hash. Do not force push, remove unrelated work, or bypass branch protections. If direct pushes are blocked, use a feature branch and pull request. Never expose tokens, passwords, or sensitive information. Never report success without evidence.

## Engineering standards

- Maintain separate vulnerable and hardened entry points and container images. No environment switch can enable vulnerable behavior in the hardened image.
- Share business models and presentation, and explicitly separate security-sensitive policy implementations. Keep controls centralized and test their effects.
- Use Python 3.13, FastAPI, SQLAlchemy, PostgreSQL, Alembic, Pydantic, Jinja2, modest JavaScript, and reproducibly locked dependencies.
- Prefer clear, small modules; no placeholder features, fabricated results, or untested compliance claims.
- Use synthetic data only. Document assumptions and actual verification limits.
- Update the roadmap, lab guides, threat model, and security mappings when implementation changes.

## Non-negotiable isolation

- All published lab ports bind explicitly to `127.0.0.1`. Never expose vulnerable services publicly or publish deployment workflows for them.
- Dedicated internal Docker networks, separate databases and volumes, no outbound Internet access from the vulnerable runtime.
- No Docker socket, sensitive host mounts, real credentials, host networking, privileged containers, or unnecessary capabilities. Use non-root users and resource limits.
- Scanners accept only named repository-created local targets from a fixed allowlist, never arbitrary URLs or CIDRs. Active testing requires explicit target selection.
- Validate source Compose AND effective runtime bindings/networks. Reset only named Aegis resources; preserve progress separately.
- Do not access external systems beyond authorized dependency/documentation retrieval and the expected project GitHub repository. Ask before changing permissions, exposing services, incurring costs, testing outside scope, or destructively affecting unrelated resources.

## Testing and documentation

- Run Ruff, MyPy, unit tests, hardened integration tests, migrations, isolation checks, Bandit, and dependency auditing for relevant changes.
- Keep expected vulnerable demonstrations in `tests/training`; never weaken hardened gates to accommodate them.
- Each lab needs a real vulnerable demonstration, hardened rejection, legitimate workflow assertion, reproducible reset, and evidence. XSS and CSRF require real browser tests; database behavior requires PostgreSQL tests in addition to fast SQLite checks.
- Use bounded timeouts. ZAP reports are scanner observations, not exploitation proof.
- Report exactly what executed, passed, failed, or remains unverified. Do not mark the full project complete until the README acceptance checklist is satisfied.
- After each milestone record features, demonstrated controls, commands/results, commit hash, exact author/committer, push status, and remaining work.
