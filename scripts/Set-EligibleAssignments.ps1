#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Makes each role-assignable group ELIGIBLE (not active) for its role, with an end date. It also reports any
    permanent ACTIVE assignment that is not a documented break-glass account.

.DESCRIPTION
    POST /roleManagement/directory/roleEligibilityScheduleRequests  (action adminAssign / adminExtend)

    Existing eligibility for the same principal and role is extended instead of duplicated.
.NOTES
    Delegated scopes: RoleEligibilitySchedule.ReadWrite.Directory, RoleAssignmentSchedule.Read.Directory, Group.Read.All
.EXAMPLE
    ./scripts/Set-EligibleAssignments.ps1 -Justification 'Quarterly governance sync CHG0012345' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Justification,
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..' 'config')
)

Import-Module (Join-Path $PSScriptRoot '..' 'modules' 'EntraGovernance' 'EntraGovernance.psm1') -Force
$config = Read-GovConfig -ConfigPath $ConfigPath
$roles = @{}; $config.Pim.roles | ForEach-Object { $roles[$_.name] = $_ }
$groupIds = Resolve-GovGroupId -Name @($config.Eligibility.assignments | ForEach-Object { $_.group })

foreach ($a in $config.Eligibility.assignments) {
    $roleId = $roles[$a.role].templateId
    $principalId = $groupIds[$a.group]
    $existing = @(Get-GovGraphAll -Uri ("/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=" +
            "principalId eq '$principalId' and roleDefinitionId eq '$roleId'"))
    $action = if ($existing.Count) { 'adminExtend' } else { 'adminAssign' }
    $body = @{
        action           = $action
        principalId      = $principalId
        roleDefinitionId = $roleId
        directoryScopeId = '/'
        justification    = $Justification
        scheduleInfo     = @{
            startDateTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            expiration    = @{ type = 'afterDuration'; duration = "P$($a.days)D" }
        }
    }
    if ($PSCmdlet.ShouldProcess("$($a.group) -> $($a.role) for $($a.days) days", $action)) {
        Invoke-GovGraph -Method POST -Uri '/v1.0/roleManagement/directory/roleEligibilityScheduleRequests' -Body $body | Out-Null
    }
}

# ---- drift check: standing (permanent, active) privileged access
$breakGlass = $config.Pim.breakGlassAccounts
$standing = foreach ($r in $config.Pim.roles | Where-Object { $_.tier -le 1 }) {
    Get-GovGraphAll -Uri ("/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=" +
        "roleDefinitionId eq '$($r.templateId)'&`$expand=principal") |
        Where-Object { $_.assignmentType -eq 'Assigned' -and -not $_.endDateTime } |
        ForEach-Object {
            $upn = $_.principal.userPrincipalName ?? $_.principal.displayName
            if ($upn -notin $breakGlass) { [pscustomobject]@{ Role = $r.name; Principal = $upn } }
        }
}
if ($standing) {
    Write-Warning "Permanent active assignments to tier 0/1 roles outside break-glass (convert to eligible):"
    $standing | Format-Table -AutoSize | Out-String | Write-Host
}
else { Write-Host 'No standing tier 0/1 access outside break-glass accounts.' -ForegroundColor Green }
