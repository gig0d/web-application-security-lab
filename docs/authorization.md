# Authorization

Authentication identifies a user; authorization decides whether that user may perform this operation on this object. The policy reads trusted database ownership and current role rather than client-supplied owner/role fields. Input models reject unexpected fields to prevent assigning ownership or privileges through ordinary create/profile payloads.

`principal` resolves a valid server session. `change` additionally enforces CSRF. `authorized_ticket` loads a ticket and asks the selected explicit policy whether the user may access it. The hardened policy allows its customer owner or a support employee/administrator. Denials return the same 404 as a nonexistent object and persist a redacted event. Read, status mutation, comments and attachment-list routes all use this shared path.

Download authorization resolves the attachment's parent ticket before returning content. It does not trust a filename, an opaque storage key or possession of a numeric ID. The separate attachment policy method makes Lab 02's missing check explicit while the hardened version delegates to object authorization.

Ticket assignment calls the server-side administrator dependency before changing state. The customer UI also hides its form as a usability decision, but that is not a security control. Lab 03 sends a direct request to prove the distinction. Role changes, audit export and synthetic resets retain an actual admin check in both variants as lab safety boundaries; the deliberate training assignment bypass does not grant arbitrary host/admin operations.

Customers cannot create or read private employee notes, even if they own the ticket. Support staff intentionally see all customer tickets and documents; HarborDesk models an internal support desk rather than isolated support-team tenancy. Profile updates change only the signed-in user's display name. Preview permission is destination-specific and does not inherit the server's broader network reachability.

The complete operation/role matrix is in [the threat model](threat-model.md#authorization-matrix-hardened). Tests exercise direct API and HTML reads, alternate child routes, writes, document download, private-note filtering, direct assignment and privilege-change invalidation. Adding another route requires placing its authorization before reading sensitive data or mutating state, then adding an unauthorized and legitimate-use regression pair.
