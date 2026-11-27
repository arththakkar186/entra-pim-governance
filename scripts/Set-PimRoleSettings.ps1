#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Applies PIM activation settings (duration, MFA / authentication context, justification, ticket, approval,
    eligibility expiry) to every Entra ID directory role listed in config/pim-role-settings.json.

.DESCRIPTION
    For each role:
      1. find the role's PIM policy  (GET /policies/roleManagementPolicyAssignments, scope "/" DirectoryRole)
      2. build the rule bodies for its tier (ConvertTo-PimPolicyRuleSet)
      3. PATCH each rule            (PATCH /policies/roleManagementPolicies/{id}/rules/{ruleId})

    Running it again with no config change sends the same values, so it is safe to re-run.
    Use -WhatIf to see the changes without sending them.

.NOTES
    Delegated scope: RoleManagementPolicy.ReadWrite.Directory (activate Privileged Role Administrator first).
.EXAMPLE
    Connect-MgGraph -Scopes RoleManagementPolicy.ReadWrite.Directory,Group.Read.All
    ./scripts/Set-PimRoleSettings.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param([string]$ConfigPath = (Join-Path $PSScriptRoot '..' 'config'))

Import-Module (Join-Path $PSScriptRoot '..' 'modules' 'EntraGovernance' 'EntraGovernance.psm1') -Force
$config = Read-GovConfig -ConfigPath $ConfigPath
$issues = Test-GovernanceConfig -Config $config
if ($issues.Count) { throw "Config is not compliant; run Test-GovernanceConfig.ps1. First issue: $($issues[0])" }

$approverNames = @($config.Pim.tiers.Values | Where-Object { $_.approverGroup } | ForEach-Object { $_.approverGroup })
$groupIds = if ($approverNames) { Resolve-GovGroupId -Name $approverNames } else { @{} }

foreach ($role in $config.Pim.roles) {
    $tier = $config.Pim.tiers[[string]$role.tier]
    $filter = "scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$($role.templateId)'"
    $assignment = @(Get-GovGraphAll -Uri "/v1.0/policies/roleManagementPolicyAssignments?`$filter=$filter")
    if ($assignment.Count -ne 1) { Write-Warning "No unique PIM policy found for '$($role.name)'; skipped."; continue }
    $policyId = $assignment[0].policyId

    $approverId = if ($tier.approverGroup) { $groupIds[$tier.approverGroup] } else { $null }
    $rules = ConvertTo-PimPolicyRuleSet -Tier $tier -ApproverGroupId $approverId

    foreach ($rule in $rules) {
        $target = "$($role.name) [tier $($role.tier)] rule $($rule.id)"
        if ($PSCmdlet.ShouldProcess($target, 'Update PIM policy rule')) {
            Invoke-GovGraph -Method PATCH -Uri "/v1.0/policies/roleManagementPolicies/$policyId/rules/$($rule.id)" -Body $rule | Out-Null
            Write-Verbose "Updated $target"
        }
    }
    Write-Host ("{0,-42} tier {1}  max {2}h  approval={3}  authContext={4}" -f $role.name, $role.tier,
        $tier.maxActivationHours, [bool]$tier.requireApproval, ($tier.authenticationContext ?? '-'))
}
