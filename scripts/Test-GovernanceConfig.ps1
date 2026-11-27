#Requires -Version 7.2
<#
.SYNOPSIS
    Offline validation of the governance config (no tenant connection). Used in CI and before every deployment.
.EXAMPLE
    ./scripts/Test-GovernanceConfig.ps1            # exit code 1 if any rule is broken
#>
[CmdletBinding()]
param([string]$ConfigPath = (Join-Path $PSScriptRoot '..' 'config'))

Import-Module (Join-Path $PSScriptRoot '..' 'modules' 'EntraGovernance' 'EntraGovernance.psm1') -Force
$config = Read-GovConfig -ConfigPath $ConfigPath
$issues = Test-GovernanceConfig -Config $config

$roles = $config.Pim.roles
Write-Host ("Roles: {0} (tier 0: {1}, tier 1: {2}, tier 2: {3}) | eligibility rules: {4} | access packages: {5} | reviews: {6}" -f `
        $roles.Count, @($roles | Where-Object { $_.tier -eq 0 }).Count, @($roles | Where-Object { $_.tier -eq 1 }).Count, @($roles | Where-Object { $_.tier -eq 2 }).Count,
    $config.Eligibility.assignments.Count, $config.Packages.packages.Count, $config.Reviews.reviews.Count)

if ($issues.Count) {
    $issues | ForEach-Object { Write-Host "  FAIL  $_" -ForegroundColor Red }
    exit 1
}
Write-Host 'Governance config is compliant.' -ForegroundColor Green
