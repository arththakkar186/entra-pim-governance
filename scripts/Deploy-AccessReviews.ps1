#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Creates or updates recurring access reviews (privileged roles, sensitive groups, guests) from config/access-reviews.json.
.DESCRIPTION
    POST / PUT /identityGovernance/accessReviews/definitions. Each definition is matched by displayName, and
    group reviews get one definition per group ("<name> - <group>").
.NOTES
    Delegated scopes: AccessReview.ReadWrite.All, Group.Read.All
.EXAMPLE
    ./scripts/Deploy-AccessReviews.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param([string]$ConfigPath = (Join-Path $PSScriptRoot '..' 'config'))

Import-Module (Join-Path $PSScriptRoot '..' 'modules' 'EntraGovernance' 'EntraGovernance.psm1') -Force
$config = Read-GovConfig -ConfigPath $ConfigPath
$uri = '/v1.0/identityGovernance/accessReviews/definitions'

$roleIds = @{}; $config.Pim.roles | ForEach-Object { $roleIds[$_.name] = $_.templateId }
$groupNames = foreach ($r in $config.Reviews.reviews) {
    if ($r.type -eq 'group') { $r.groups }
    if ($r.reviewers.type -eq 'group') { $r.reviewers.group }
}
$groupIds = if ($groupNames) { Resolve-GovGroupId -Name @($groupNames) } else { @{} }
$existing = @(Get-GovGraphAll -Uri "$uri`?`$select=id,displayName")

# Expand group reviews into one definition per group.
$definitions = foreach ($r in $config.Reviews.reviews) {
    if ($r.type -eq 'group') {
        foreach ($g in $r.groups) {
            $copy = $r.Clone(); $copy.groups = @($g); $copy.name = "$($r.name) - $g"; $copy
        }
    }
    else { $r }
}

foreach ($d in $definitions) {
    $body = ConvertTo-AccessReviewBody -Review $d -RoleIds $roleIds -GroupIds $groupIds
    $match = $existing | Where-Object { $_.displayName -eq $d.name } | Select-Object -First 1
    if ($match) {
        if ($PSCmdlet.ShouldProcess($d.name, 'Update access review')) {
            Invoke-MgGraphRequest -Method PUT -Uri "$uri/$($match.id)" -Body ($body | ConvertTo-Json -Depth 20) -ContentType 'application/json' | Out-Null
        }
    }
    elseif ($PSCmdlet.ShouldProcess($d.name, 'Create access review')) {
        Invoke-GovGraph -Method POST -Uri $uri -Body $body | Out-Null
    }
    Write-Host ("{0,-60} {1,-9} default={2} autoApply={3}" -f $d.name, $d.frequency, $d.defaultDecision, $d.autoApply)
}
