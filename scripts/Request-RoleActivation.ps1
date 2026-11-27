#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Administrator self-service: activate an eligible Entra role just in time, with justification, ticket and duration.
.DESCRIPTION
    POST /roleManagement/directory/roleAssignmentScheduleRequests  action = selfActivate.
    The PIM policy enforces the tier's rules (MFA or authentication context, approval, maximum duration).
    A request longer than the maximum is rejected by Entra, not shortened.
.EXAMPLE
    Connect-MgGraph -Scopes RoleAssignmentSchedule.ReadWrite.Directory
    ./scripts/Request-RoleActivation.ps1 -Role 'Exchange Administrator' -Hours 2 -Ticket INC0012345 `
        -Justification 'Fix mail flow connector for INC0012345'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Role,
    [Parameter(Mandatory)][ValidateLength(15, 500)][string]$Justification,
    [ValidateRange(1, 8)][int]$Hours = 1,
    [string]$Ticket,
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..' 'config')
)

Import-Module (Join-Path $PSScriptRoot '..' 'modules' 'EntraGovernance' 'EntraGovernance.psm1') -Force
$config = Read-GovConfig -ConfigPath $ConfigPath
$r = $config.Pim.roles | Where-Object { $_.name -eq $Role }
if (-not $r) { throw "Role '$Role' is not managed by this repository." }
$tier = $config.Pim.tiers[[string]$r.tier]
if ($Hours -gt $tier.maxActivationHours) { throw "Tier $($r.tier) allows at most $($tier.maxActivationHours) hour(s)." }
if ($tier.requireTicket -and -not $Ticket) { throw "Tier $($r.tier) requires -Ticket." }

$me = Invoke-GovGraph -Uri '/v1.0/me?$select=id,userPrincipalName'
$body = @{
    action           = 'selfActivate'
    principalId      = $me.id
    roleDefinitionId = $r.templateId
    directoryScopeId = '/'
    justification    = $Justification
    scheduleInfo     = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        expiration    = @{ type = 'afterDuration'; duration = "PT$($Hours)H" }
    }
}
if ($Ticket) { $body.ticketInfo = @{ ticketNumber = $Ticket; ticketSystem = 'ServiceNow' } }

if ($PSCmdlet.ShouldProcess("$Role for $Hours h as $($me.userPrincipalName)", 'Activate')) {
    $res = Invoke-GovGraph -Method POST -Uri '/v1.0/roleManagement/directory/roleAssignmentScheduleRequests' -Body $body
    $hint = if ($res.status -eq 'PendingApproval') { ' - waiting for an approver in the Tier 0 approver group' } else { '' }
    Write-Host "Request $($res.id): $($res.status)$hint"
}
