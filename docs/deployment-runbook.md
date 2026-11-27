# Deployment Runbook

## Prerequisites (one-time, manual)

1. Two break-glass accounts created and tested ([break-glass.md](break-glass.md)).
2. Entra ID P2 or Entra ID Governance licences for everyone who will be eligible or reviewed.
3. Authentication context `c1` and its Conditional Access policy in **report-only** mode for 1 week, then on.
4. Role-assignable groups created: `PIM-Role-*`, `PIM-Approvers-Tier0`, `PIM-Approvers-Tier1`, the requestor team groups.

## Order of operations

| Step | Command | Check |
|---|---|---|
| 1 | `./scripts/Test-GovernanceConfig.ps1` | "compliant" |
| 2 | `./scripts/Set-PimRoleSettings.ps1 -WhatIf`, then without `-WhatIf` | Spot-check two roles in the portal (PIM → Roles → Settings) |
| 3 | `./scripts/Set-EligibleAssignments.ps1 -Justification '<change>' -WhatIf`, then apply | Groups show as eligible with end dates |
| 4 | Move current admins: add each to the right `PIM-Role-*` group, **then** remove their permanent assignment | Drift check shows 0 standing assignments outside break-glass |
| 5 | `./scripts/Deploy-AccessPackages.ps1 -WhatIf`, then apply | Request a package as a test user |
| 6 | `./scripts/Deploy-AccessReviews.ps1 -WhatIf`, then apply | Reviews show with the next start date |
| 7 | `./scripts/Get-PrivilegedAccessReport.ps1` | `summary.md` standing access = 0 |

Step 4 is the risky one. Do it role by role, Tier 2 first and Tier 0 last, and confirm each admin can activate before removing
their permanent assignment. Communicate the change and the activation steps beforehand.

## Rollback

| Change | Rollback |
|---|---|
| PIM policy rules | Revert the commit and re-run `Set-PimRoleSettings.ps1` (the previous values are in Git) |
| Eligibility | `adminRemove` request for the schedule; re-add the permanent assignment only as a documented emergency |
| Access package / policy | Revert and re-deploy; existing assignments stay until they expire |
| Access review | Stop the review instance in the portal; revert and re-deploy the definition |
| Locked out | Break-glass account |

## Monthly operations

1. Run `Get-PrivilegedAccessReport.ps1`. Standing access must be 0.
2. Read `activations.csv`: are Tier 0 activations matched to tickets? Are there out-of-hours activations?
3. Eligible but never activated in 90 days → raise for removal in the next review.
4. `expiring.csv` → remind owners to re-request through the access package.
