#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Read-only monthly report on privileged access: who is eligible, who holds active access now (and whether
    it is time-bound), who activated what in the period, and eligibility expiring in the next 30 days.
.OUTPUTS
    out/<yyyy-MM>/eligible.csv, active.csv, activations.csv, expiring.csv, summary.md
.NOTES
    Delegated scopes: RoleManagement.Read.Directory, AuditLog.Read.All
.EXAMPLE
    ./scripts/Get-PrivilegedAccessReport.ps1 -Days 30
#>
[CmdletBinding()]
param(
    [int]$Days = 30,
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..' 'config'),
    [string]$OutPath = (Join-Path $PSScriptRoot '..' 'out' (Get-Date -Format 'yyyy-MM'))
)

Import-Module (Join-Path $PSScriptRoot '..' 'modules' 'EntraGovernance' 'EntraGovernance.psm1') -Force
$config = Read-GovConfig -ConfigPath $ConfigPath
New-Item -ItemType Directory -Force -Path $OutPath | Out-Null
$roles = @{}; $config.Pim.roles | ForEach-Object { $roles[$_.templateId] = $_ }
$now = (Get-Date).ToUniversalTime()
$name = { param($p) $p.userPrincipalName ?? $p.displayName }

$eligible = Get-GovGraphAll -Uri '/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal' |
    Where-Object { $roles.ContainsKey($_.roleDefinitionId) } |
    ForEach-Object {
        [pscustomobject]@{
            Role = $roles[$_.roleDefinitionId].name; Tier = $roles[$_.roleDefinitionId].tier
            Principal = & $name $_.principal; Type = $_.principal.'@odata.type' -replace '#microsoft.graph.', ''
            Start = $_.startDateTime; End = $_.endDateTime
        }
    }

$active = Get-GovGraphAll -Uri '/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal' |
    Where-Object { $roles.ContainsKey($_.roleDefinitionId) } |
    ForEach-Object {
        $upn = & $name $_.principal
        [pscustomobject]@{
            Role = $roles[$_.roleDefinitionId].name; Tier = $roles[$_.roleDefinitionId].tier; Principal = $upn
            AssignmentType = $_.assignmentType      # Activated (JIT) or Assigned (direct)
            End = $_.endDateTime
            Finding = if ($_.assignmentType -eq 'Assigned' -and -not $_.endDateTime -and $upn -notin $config.Pim.breakGlassAccounts) { 'STANDING ACCESS' } else { '' }
        }
    }

$since = $now.AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
$activations = Get-GovGraphAll -Uri ("/v1.0/auditLogs/directoryAudits?`$filter=loggedByService eq 'PIM' and " +
    "activityDisplayName eq 'Add member to role completed (PIM activation)' and activityDateTime ge $since") |
    ForEach-Object {
        [pscustomobject]@{
            When          = $_.activityDateTime
            Who           = $_.initiatedBy.user.userPrincipalName
            Role          = ($_.targetResources | Where-Object { $_.type -eq 'Role' } | Select-Object -First 1).displayName
            Justification = $_.resultReason
        }
    }

$expiring = $eligible | Where-Object { $_.End -and ([datetime]$_.End) -lt $now.AddDays(30) }

$eligible | Export-Csv (Join-Path $OutPath 'eligible.csv') -NoTypeInformation
$active | Export-Csv (Join-Path $OutPath 'active.csv') -NoTypeInformation
$activations | Export-Csv (Join-Path $OutPath 'activations.csv') -NoTypeInformation
$expiring | Export-Csv (Join-Path $OutPath 'expiring.csv') -NoTypeInformation

$standing = @($active | Where-Object { $_.Finding })
@"
# Privileged access report ($($now.ToString('yyyy-MM-dd')))

| Measure | Value |
|---|---:|
| Eligible assignments | $(@($eligible).Count) |
| Active right now | $(@($active).Count) |
| ...of which standing (permanent, not break-glass) | **$($standing.Count)** |
| PIM activations in the last $Days days | $(@($activations).Count) |
| Eligibility expiring in 30 days | $(@($expiring).Count) |

Standing access should be **0**. Every entry in active.csv marked STANDING ACCESS must be converted to eligible
or documented as an exception.
"@ | Set-Content (Join-Path $OutPath 'summary.md')

Write-Host "Report written to $OutPath (standing access findings: $($standing.Count))"
