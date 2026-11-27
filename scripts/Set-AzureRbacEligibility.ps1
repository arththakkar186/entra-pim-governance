#Requires -Version 7.2
#Requires -Modules Az.Accounts
<#
.SYNOPSIS
    Same just-in-time model for Azure resource roles (Owner, Contributor, User Access Administrator) at
    subscription scope: makes a group ELIGIBLE through the ARM PIM API instead of holding a permanent assignment.
.DESCRIPTION
    PUT {scope}/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/{guid}?api-version=2020-10-01
    Activation rules for Azure roles are set per role and scope in roleManagementPolicies (same rule model as Entra).
.EXAMPLE
    Connect-AzAccount
    ./scripts/Set-AzureRbacEligibility.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 `
        -GroupObjectId 11111111-1111-1111-1111-111111111111 -Role Contributor -Days 180 -Justification 'Platform team JIT' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][guid]$GroupObjectId,
    [ValidateSet('Owner', 'Contributor', 'User Access Administrator', 'Reader')][string]$Role = 'Contributor',
    [ValidateRange(1, 365)][int]$Days = 180,
    [Parameter(Mandatory)][string]$Justification
)

# Built-in Azure role definition IDs (the same in every tenant).
$roleIds = @{
    'Owner'                     = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
    'Contributor'               = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
    'User Access Administrator' = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
    'Reader'                    = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
}
$scope = "/subscriptions/$SubscriptionId"
$body = @{
    properties = @{
        principalId      = "$GroupObjectId"
        roleDefinitionId = "$scope/providers/Microsoft.Authorization/roleDefinitions/$($roleIds[$Role])"
        requestType      = 'AdminAssign'
        justification    = $Justification
        scheduleInfo     = @{
            startDateTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            expiration    = @{ type = 'AfterDuration'; duration = "P$($Days)D" }
        }
    }
} | ConvertTo-Json -Depth 10

$path = "$scope/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/$([guid]::NewGuid())?api-version=2020-10-01"
if ($PSCmdlet.ShouldProcess("$GroupObjectId eligible for $Role on $scope ($Days days)", 'AdminAssign')) {
    $res = Invoke-AzRestMethod -Method PUT -Path $path -Payload $body
    if ($res.StatusCode -ge 300) { throw "ARM returned $($res.StatusCode): $($res.Content)" }
    Write-Host "Eligibility request created: $(($res.Content | ConvertFrom-Json).properties.status)"
}
