# Engineering milestone ledger

Each listed main-branch commit was inspected after creation and pushed to the exact authorized origin, with its remote hash verified. No history was rewritten.

Author for each listed commit: Giovanny Alvarado Barrantes <gioab0411@gmail.com>

Committer for each listed commit: Giovanny Alvarado Barrantes <gioab0411@gmail.com>

| Commit | Concrete result | Executed verification | Push |
| --- | --- | --- | --- |
| `ce77311` | HarborDesk workflows, distinct policies/images, 12 scenarios, control center, source isolation | 79 API/unit/isolation/training tests passed; PostgreSQL skipped locally; 9 browser checks passed; Ruff/MyPy/Bandit/pip-audit passed | Verified |
| `1a44842` | Hardened CI, separate training workflow, authenticated bounded ZAP plans, threat model and security documentation | 54 focused controller/training/isolation tests passed; scope and static checks passed; hosted PostgreSQL job subsequently passed | Verified |
| `21a4766` | Removed automatic bot-authored dependency development configuration | Removal inspected against explicit authorship contract | Verified |
| `66c08c1` | Resolved Compose configuration includes disabled scanner profile without starting it | 20 isolated configuration/lifecycle regressions passed | Verified |
| `f33bd02` | Corrected complete tmpfs mount strings after an actual Docker startup error | 21 configuration/lifecycle regressions passed; new temporary-path lint false positives addressed in the subsequent source revision | Verified |

The removed dependency-update configuration briefly generated one bot-authored PR on a separate branch. It was closed without merging, and no bot commit entered `main`. Automatic updates remain disabled; no bot history is rewritten or concealed. Accepted development history uses only the exact owner identity above.

The initial hosted container failures were useful integration evidence, not successful deployments: first disabled-profile inventory rendering, then incorrectly split tmpfs options. Refer to `verification.md` and actual GitHub Actions runs for later results. The full definition of done remains governed by measured acceptance checks rather than this commit count.
