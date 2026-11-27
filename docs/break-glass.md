# Break-Glass (Emergency Access) Accounts

Two accounts keep the tenant recoverable if PIM, Conditional Access, MFA or federation fails.

| Property | Value |
|---|---|
| Accounts | `bg-admin-01@<tenant>.onmicrosoft.com`, `bg-admin-02@...` (cloud-only, on the initial domain, no federation dependency) |
| Role | Global Administrator, **permanent active**: the only exception to zero standing access |
| Authentication | FIDO2 security key per account (two keys each), stored in separate safes. Password in a sealed envelope as fallback |
| Conditional Access | Excluded from all policies except one that requires the FIDO2 authentication strength for these accounts only |
| Licences, mailbox | None |
| Monitoring | Any sign-in or audit event by either account raises a high-severity alert to the security on-call team |
| Usage | Only when normal admin access is impossible. Every use is followed by a post-incident review and credential rotation |

## Quarterly test

1. Two people retrieve one key from the safe and log the action.
2. Sign in to the Entra admin center with `bg-admin-01` and confirm Global Administrator is active.
3. Confirm the alert fired within 5 minutes.
4. Sign out and return the key. Record the test (date, people, alert time).
5. Alternate accounts each quarter.

## Why they are listed in config

`breakGlassAccounts` in `pim-role-settings.json` lets the drift check and the monthly report **exclude** exactly these two
accounts from "standing access" findings and flag every other permanent assignment. The validator also requires that two are listed.
