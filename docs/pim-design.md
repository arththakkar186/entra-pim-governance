# PIM Design

## Tiering rationale

A role's tier is based on **what an attacker could do with it**, not on how often it is used.

| Tier | Test | Examples |
|---|---|---|
| 0 | Can it grant itself or others any role, change authentication, or turn off security controls? | Global Admin, Privileged Role Admin, Privileged Authentication Admin, Conditional Access Admin, Security Admin |
| 1 | Can it read or change one workload's data, or many users' data? | Exchange, SharePoint, Intune, User Admin, Authentication Admin, Application Admin |
| 2 | Limited support or read-only | Helpdesk Admin, Global Reader |

Application Administrator is Tier 1 here, but it can add credentials to service principals that may hold Tier 0
application permissions. Tenants with highly privileged app registrations should move it to Tier 0.

## Policy rules (what `ConvertTo-PimPolicyRuleSet` sets)

Each directory role has one PIM policy. Its rules have fixed IDs:

| Rule ID | Setting | Tier 0 | Tier 1 | Tier 2 |
|---|---|---|---|---|
| `Expiration_EndUser_Assignment` | Max activation | PT2H | PT8H | PT8H |
| `Enablement_EndUser_Assignment` | Required on activation | Justification, Ticketing | MFA, Justification, Ticketing | MFA, Justification |
| `AuthenticationContext_EndUser_Assignment` | CA authentication context | `c1` | off | off |
| `Approval_EndUser_Assignment` | Approval | Tier 0 approver group, 1 day timeout, approver justification | off | off |
| `Expiration_Admin_Eligibility` | Max eligibility | P180D | P365D | P365D |
| `Expiration_Admin_Assignment` | Max direct active assignment by an admin | P15D | P15D | P15D |

Permanent eligibility and permanent active assignment are both disallowed. The only permanent role holders are the break-glass
accounts, which are assigned outside PIM policy.

## Authentication context for Tier 0

1. Create authentication context `c1` "Privileged role activation" (Entra ID → Conditional Access → Authentication contexts).
2. Create a Conditional Access policy: *All users* (exclude break-glass), target resource = authentication context `c1`,
   grant = **Require authentication strength: Phishing-resistant MFA**, session sign-in frequency = every time.
3. The PIM Tier 0 rule references `c1`. Activation then triggers a fresh phishing-resistant sign-in.

PIM's built-in "require MFA" rule is satisfied by any MFA method, including SMS. The authentication context is what makes
the requirement phishing-resistant.

## Approvers

- Tier 0 approvers are a small group (security lead plus IAM lead plus a deputy). Approvers cannot approve their own requests (PIM enforces this).
- Approvers must give a justification for each decision. A request times out after 1 day.

## Alerts (PIM built-in plus SIEM)

| Alert | Source |
|---|---|
| Role activated outside business hours (Tier 0) | Audit log → SIEM |
| Roles assigned outside PIM | PIM alerts + `Set-EligibleAssignments.ps1` drift check |
| Too many Global Administrators (> 5 eligible) | PIM alert |
| Eligible but never activated in 90 days | Monthly report → candidate for removal in the next review |
