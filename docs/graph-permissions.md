# Microsoft Graph Permissions (least privilege)

Delegated scopes, used interactively by an administrator who has activated the matching role through PIM.

| Script | Scopes | Entra role to activate |
|---|---|---|
| `Test-GovernanceConfig.ps1` | none (offline) | none |
| `Set-PimRoleSettings.ps1` | `RoleManagementPolicy.ReadWrite.Directory`, `Group.Read.All` | Privileged Role Administrator |
| `Set-EligibleAssignments.ps1` | `RoleEligibilitySchedule.ReadWrite.Directory`, `RoleAssignmentSchedule.Read.Directory`, `Group.Read.All` | Privileged Role Administrator |
| `Deploy-AccessPackages.ps1` | `EntitlementManagement.ReadWrite.All`, `Group.Read.All` | Identity Governance Administrator (+ owner of role-assignable groups, or Privileged Role Administrator, to add them to a catalog) |
| `Deploy-AccessReviews.ps1` | `AccessReview.ReadWrite.All`, `Group.Read.All` | Identity Governance Administrator (Privileged Role Administrator for role reviews) |
| `Get-PrivilegedAccessReport.ps1` | `RoleManagement.Read.Directory`, `AuditLog.Read.All` | Global Reader + Reports Reader (or Security Reader) |
| `Request-RoleActivation.ps1` | `RoleAssignmentSchedule.ReadWrite.Directory` | The eligible role itself |
| `Set-AzureRbacEligibility.ps1` | Azure Resource Manager (Az.Accounts) | Owner or User Access Administrator on the subscription |

## Unattended report (optional)

For a scheduled monthly report, use an app registration with **application** permissions
`RoleManagement.Read.Directory` and `AuditLog.Read.All` only, authenticated with a certificate (no client secret), run from
an Azure Automation account with a managed identity where possible. **Do not** give an unattended identity any `ReadWrite`
governance permission. Changes stay interactive, previewed and reviewed.
