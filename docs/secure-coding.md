# Secure coding decisions

**Preserve interpretation boundaries.** Hardened search constructs SQLAlchemy expressions with bound values rather than interpolating user input. Wildcard escaping additionally makes searches literal; it is not the SQL-injection defense. HTML comments/query echoes are escaped at the final HTML text-node sink. Static JavaScript builds DOM nodes and assigns `textContent`; it does not use input as `innerHTML`. A restrictive CSP limits executable sources and framing, providing defense in depth rather than repairing an unsafe HTML sink.

**Authorize server-side objects and functions.** Every sensitive route uses trusted principal, object and role checks. Input schemas forbid extra fields; no profile payload can supply another user's ID or role. A missing button, random-looking ID or attachment key is not authorization. Session roles are not frozen inside a client token.

**Keep uploads inert.** The only supported document format is bounded UTF-8 plain text. Validate a normalized safe filename, expected extension and control characters. Generate a storage key independent of the filename and keep bytes in the database. Force `text/plain`, `attachment` and `nosniff` on download. The training variant intentionally retains unsafe metadata but still cannot write a host path or execute a server program.

**Bound work at several layers.** Request bodies are capped before multipart parsing, hardened files at 64 KiB, training files at a separate 128 KiB safety ceiling, previews at 4 KiB/two seconds, query results at fifty, scan jobs by duration/thread and containers by CPU/memory/process count. PostgreSQL runtime roles have statement/lock/idle-transaction timeouts. These controls reduce the experiment's blast radius; they do not prove resistance to all denial-of-service techniques.

**Avoid arbitrary network destinations.** Even the vulnerable preview accepts only fixed internal fixture selectors. Hardened authorization narrows them to the public handbook. No redirects, environment proxy settings, arbitrary schemes/hosts/ports, real metadata endpoint or Internet URL is accepted. Internal Docker networks provide an independent egress boundary.

**Handle errors without reflecting secrets.** Validation failures do not serialize Pydantic's original input values. Unexpected exceptions return a generic message and request ID. Synthetic debug exposure in Lab 12 consists of fixed harmless training values, never actual environment variables or tracebacks. Audit events use server-defined event categories and identifiers, not passwords, cookies or document text.

**Separate operational authority.** Migration ownership is not a runtime application permission. Containers do not run as root or hold the Docker socket. Host lifecycle commands are argument arrays with fixed project/service names, never shell fragments from an HTTP request. Reset is limited to synthetic records or exact project business volumes. Credentials, notebooks and test artifacts stay ignored.

See the corresponding lab guides for the precise unsafe override and secure method. These decisions address selected requirements; they do not establish complete OWASP category coverage or production readiness.
