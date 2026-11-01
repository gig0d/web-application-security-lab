# Demonstration walkthrough

Allow about twenty minutes for a focused presentation after images are built. Use a fresh synthetic reset and keep the terminal available for verification. Do not present screenshots as current results unless their recorded execution matches the demonstration.

## 1. Establish scope and normal behavior

Show `python -m scripts.lab inspect`, then the loopback addresses in the control center. Explain the two databases and distinct application images. Open hardened HarborDesk as Alice, create a fictional request, add a public comment, upload a small `notes.txt`, download it, close the ticket and update the display name. This establishes what the application must continue supporting after a fix.

Open a separate browser profile/context for Bob or sign out before switching identities. Browser cookies are shared across tabs and names are shared across ports unless deliberately distinct; Aegis uses separate names for the two variants.

## 2. Show a permission failure and its fix

Use Lab 01. As Alice, open ticket 2 in vulnerable HarborDesk and observe Bob's fictional renewal. Repeat in hardened HarborDesk and observe 404. Access Alice's ticket 1 to show legitimate behavior still works. Run the named paired regression test and point to both status observations rather than merely describing the policy.

Use Lab 03 briefly: the customer's assignment form is absent in both pages, yet only hardened HarborDesk rejects the direct customer request. Explain why a visible button is a user-experience feature and the server check is the permission boundary.

## 3. Show interpretation and browser evidence

Use the Lab 04 read-only boolean search example. Compare returned ticket IDs and show the difference between interpolated SQL and bound SQLAlchemy values. Explain that LIKE wildcard escaping improves search semantics while parameter binding prevents structural injection.

Run stored/reflected XSS browser tests. The proof sets only a local DOM attribute; no data is exfiltrated. Show the marker in training and literal escaped text in hardened HarborDesk. Explain CSP as a second barrier. Then describe the CSRF browser fixture: another loopback port is cross-origin but same-site, so cookie strategy alone cannot replace the synchronizer token.

## 4. Show a lifecycle or service boundary

Use Lab 09 to replay a synthetic token after logout without showing its raw value in recorded evidence. Or use Lab 11: handbook succeeds, synthetic private metadata succeeds only in training, and no variant accepts a URL. Explain why the constrained simulator teaches the intermediary trust failure without reaching real metadata or external systems.

## 5. Export evidence and restore

Save a notebook observation, distinguish review status from verification, and export JSON/Markdown. Point to actual timestamps/observations, selected standards mappings, residual risks and absent scanner evidence. If a genuine ZAP report exists, compare one observed alert with the manual finding and explain its limitations; otherwise state that no scan has run.

Perform the confirmed synthetic data reset, sign in again, and show the independent notebook still present. Stop the project with its scoped teardown command. End by naming the most important remaining validation in `verification.md`, rather than claiming the application is generally secure or standards-compliant.
