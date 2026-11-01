# Authentication and sessions

The four documented accounts are fictional fixtures. They all use the public local-only password from the README to make comparison reproducible; this is an explicit training exception, not a recommendation for operational accounts. There is no registration, password reset, email verification or multi-factor flow.

Passwords are hashed with maintained `argon2-cffi` defaults using Argon2id, independent random salts and encoded parameters. Login verifies a dummy hash for unknown users and returns the same hardened 401 body for unknown usernames and wrong passwords. Successful verification rehashes when the configured library policy changes. Inputs have length limits and unexpected fields are rejected without reflecting submitted passwords in validation errors.

The hardened rate limiter persists one-minute hashed account and direct-client buckets. A process lock serializes bucket checks for the configured single Uvicorn worker; limits are five account attempts and twenty client attempts per minute. Failed attempts commit before returning errors. The threshold returns 429 without permanent account lockout. A shared workstation or repeated automated lesson can exhaust a bucket; wait sixty seconds or perform the confirmed synthetic reset. Distributed workers would need transactional/shared enforcement; the current container intentionally uses one worker.

Every successful login issues a fresh 256-bit random reference token and invalidates any prior token supplied by that browser. Only its SHA-256 digest is stored server-side. The database session includes a random synchronizer CSRF token, expiry (default thirty minutes), user ID and session-version snapshot. The principal dependency reloads the user and checks expiry/version on every request. Administrative role changes increment the version, invalidating existing sessions immediately.

Logout requires a valid CSRF token and deletes the backend session in the hardened implementation. The training policy deliberately omits that deletion for Lab 09; replaying the prior cookie exposes the difference. Invalid, excessive-length and expired cookies fail closed.

Cookies are HttpOnly, path `/`, SameSite=Lax and time-limited. Variants use different cookie names because browser cookies are not isolated by port. This lab runs loopback HTTP, so Secure is deliberately disabled; `AEGIS_SECURE_COOKIE=true` is supported only when an appropriate local TLS origin is provided. No HSTS/TLS assurance or complete ASVS authentication compliance is claimed.

## CSRF architecture

Authenticated mutations use the session-bound `X-CSRF-Token` header and constant-time comparison, plus an exact Origin check when supplied. Static same-origin JavaScript reads the token from its rendered page. The session endpoint is same-origin readable and responses are not cached. Cross-origin form submissions cannot set that header; cross-origin JavaScript cannot obtain credentialed responses because hardened CORS sharing is not enabled.

Login accepts typed JSON, so a cross-origin simple HTML form cannot submit its expected content type, and supplied Origin must match the configured loopback origin. This provides a different pre-authentication boundary from the synchronizer token used after login. SameSite alone does not stop same-site cross-origin requests from another loopback port; the browser lab demonstrates this distinction.

See `tests/integration/test_hardened.py`, Labs 07–09, and [limitations](limitations.md). No measured constant-time end-to-end login or distributed throttling claim is made.
