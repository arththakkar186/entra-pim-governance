#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Creates or updates entitlement-management catalogs, access packages, their group resources and their
    assignment policy (requestors, approval stages, expiry, recurring review) from config/access-packages.json.

.DESCRIPTION
    Graph v1.0, /identityGovernance/entitlementManagement:
      catalogs                         find by displayName, else POST
      resourceRequests (adminAdd)      add each group to its catalog (skipped if already there)
      accessPackages                   find by displayName in the catalog, else POST
      accessPackages/{id}/resourceRoleScopes   add group Member role to the package
      assignmentPolicies               find "<package> - standard policy", PUT if it exists, else POST
.NOTES
    Delegated scopes: EntitlementManagement.ReadWrite.All, Group.Read.All
.EXAMPLE
    ./scripts/Deploy-AccessPackages.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param([string]$ConfigPath = (Join-Path $PSScriptRoot '..' 'config'))

Import-Module (Join-Path $PSScriptRoot '..' 'modules' 'EntraGovernance' 'EntraGovernance.psm1') -Force
$config = Read-GovConfig -ConfigPath $ConfigPath
$em = '/v1.0/identityGovernance/entitlementManagement'
$esc = { param($s) $s.Replace("'", "''") }

$names = foreach ($p in $config.Packages.packages) {
    $p.resources | ForEach-Object { $_.name }
    if ($p.policy.requestors.group) { $p.policy.requestors.group }
    $p.policy.approval.stages | Where-Object { $_.group } | ForEach-Object { $_.group }
    if ($p.policy.review.reviewerGroup) { $p.policy.review.reviewerGroup }
}
$groupIds = Resolve-GovGroupId -Name @($names)

# ---- catalogs
$catalogIds = @{}
foreach ($c in $config.Packages.catalogs) {
    $found = @(Get-GovGraphAll -Uri "$em/catalogs?`$filter=displayName eq '$(& $esc $c.name)'")
    if ($found.Count) { $catalogIds[$c.name] = $found[0].id; continue }
    if ($PSCmdlet.ShouldProcess($c.name, 'Create catalog')) {
        $new = Invoke-GovGraph -Method POST -Uri "$em/catalogs" -Body @{
            displayName = $c.name; description = $c.description; state = 'published'; isExternallyVisible = [bool]$c.externallyVisible }
        $catalogIds[$c.name] = $new.id
    }
}

foreach ($p in $config.Packages.packages) {
    $catalogId = $catalogIds[$p.catalog]
    if (-not $catalogId) { Write-Host "[WhatIf] package '$($p.name)' would be created in new catalog '$($p.catalog)'"; continue }

    # ---- resources into the catalog
    $catalogResources = @(Get-GovGraphAll -Uri "$em/catalogs/$catalogId/resources?`$select=id,originId")
    foreach ($r in $p.resources) {
        $gid = $groupIds[$r.name]
        if ($catalogResources.originId -contains $gid) { continue }
        if ($PSCmdlet.ShouldProcess("$($r.name) -> $($p.catalog)", 'Add group to catalog')) {
            Invoke-GovGraph -Method POST -Uri "$em/resourceRequests" -Body @{
                requestType = 'adminAdd'
                resource    = @{ originId = $gid; originSystem = 'AadGroup' }
                catalog     = @{ id = $catalogId }
            } | Out-Null
        }
    }

    # ---- access package
    $pkg = @(Get-GovGraphAll -Uri "$em/accessPackages?`$filter=displayName eq '$(& $esc $p.name)'&`$expand=catalog") |
        Where-Object { $_.catalog.id -eq $catalogId } | Select-Object -First 1
    if (-not $pkg) {
        if (-not $PSCmdlet.ShouldProcess($p.name, 'Create access package')) { continue }
        $pkg = Invoke-GovGraph -Method POST -Uri "$em/accessPackages" -Body @{
            displayName = $p.name; description = "Managed by entra-pim-governance."; isHidden = $false; catalog = @{ id = $catalogId } }
    }

    # ---- resource role scopes (group Member)
    $scopes = @(Get-GovGraphAll -Uri "$em/accessPackages/$($pkg.id)?`$expand=resourceRoleScopes(`$expand=role,scope)" |
            ForEach-Object { $_.resourceRoleScopes })
    foreach ($r in $p.resources) {
        $gid = $groupIds[$r.name]
        if ($scopes | Where-Object { $_.scope.originId -eq $gid }) { continue }
        if ($PSCmdlet.ShouldProcess("$($r.name) ($($r.role)) -> $($p.name)", 'Add resource role')) {
            $res = @(Get-GovGraphAll -Uri "$em/catalogs/$catalogId/resources?`$filter=originId eq '$gid'&`$expand=roles,scopes")[0]
            $role = $res.roles | Where-Object { $_.displayName -eq $r.role } | Select-Object -First 1
            Invoke-GovGraph -Method POST -Uri "$em/accessPackages/$($pkg.id)/resourceRoleScopes" -Body @{
                role  = @{ originId = $role.originId; originSystem = 'AadGroup'; resource = @{ id = $res.id } }
                scope = @{ originId = $gid; originSystem = 'AadGroup'; isRootScope = $true }
            } | Out-Null
        }
    }

    # ---- assignment policy
    $body = ConvertTo-AssignmentPolicyBody -Package $p -AccessPackageId $pkg.id -GroupIds $groupIds
    $existing = @(Get-GovGraphAll -Uri "$em/assignmentPolicies?`$filter=accessPackage/id eq '$($pkg.id)'") |
        Where-Object { $_.displayName -eq $body.displayName } | Select-Object -First 1
    if ($existing) {
        if ($PSCmdlet.ShouldProcess($body.displayName, 'Replace assignment policy')) {
            Invoke-MgGraphRequest -Method PUT -Uri "$em/assignmentPolicies/$($existing.id)" -Body ($body | ConvertTo-Json -Depth 20) -ContentType 'application/json' | Out-Null
        }
    }
    elseif ($PSCmdlet.ShouldProcess($body.displayName, 'Create assignment policy')) {
        Invoke-GovGraph -Method POST -Uri "$em/assignmentPolicies" -Body $body | Out-Null
    }
    Write-Host ("{0,-36} expires {1,3}d  approvals {2}  review {3}" -f $p.name, $p.policy.expirationDays,
        @($p.policy.approval.stages).Count, $p.policy.review.frequency)
}
