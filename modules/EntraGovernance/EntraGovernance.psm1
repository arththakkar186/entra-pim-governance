#Requires -Version 7.2
<#
    EntraGovernance: shared functions for the PIM / entitlement management / access review scripts.

    Two kinds of function live here:
      * Pure builders and validators (no network). They turn config JSON into Microsoft Graph request
        bodies and check the config against the governance rules. Pester tests cover these.
      * Thin Graph helpers built on Invoke-MgGraphRequest (Microsoft.Graph.Authentication).
#>
Set-StrictMode -Version Latest

# ------------------------------------------------------------------------------------------ config

function Read-GovConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigPath)
    $read = { param($name) Get-Content -Raw -Path (Join-Path $ConfigPath $name) | ConvertFrom-Json -AsHashtable }
    [ordered]@{
        Pim         = & $read 'pim-role-settings.json'
        Eligibility = & $read 'eligible-assignments.json'
        Packages    = & $read 'access-packages.json'
        Reviews     = & $read 'access-reviews.json'
    }
}

function Test-GovernanceConfig {
    <#
    .SYNOPSIS
        Checks the config against the governance rules. Returns one string per problem (empty = compliant).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Config)

    $issues = [System.Collections.Generic.List[string]]::new()
    $guid = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    $pim = $Config.Pim

    if (@($pim.breakGlassAccounts).Count -lt 2) {
        $issues.Add('At least two break-glass accounts must be documented (breakGlassAccounts).')
    }

    foreach ($t in $pim.tiers.Keys) {
        $s = $pim.tiers[$t]
        if ($s.maxActivationHours -gt 8) { $issues.Add("Tier ${t}: maxActivationHours $($s.maxActivationHours) exceeds 8.") }
        if (-not $s.requireJustification) { $issues.Add("Tier ${t}: justification must be required on activation.") }
        if (-not $s.requireMfa -and -not $s.authenticationContext) {
            $issues.Add("Tier ${t}: activation needs MFA or an authentication context.")
        }
        if ($s.eligibilityMaxDays -gt 365) { $issues.Add("Tier ${t}: eligibility longer than 365 days.") }
    }
    $t0 = $pim.tiers['0']
    if ($t0) {
        if (-not $t0.requireApproval -or -not $t0.approverGroup) { $issues.Add('Tier 0: activation must require approval by an approver group.') }
        if ($t0.maxActivationHours -gt 4) { $issues.Add('Tier 0: maxActivationHours must be 4 or less.') }
        if (-not $t0.authenticationContext) { $issues.Add('Tier 0: an authentication context (phishing-resistant MFA via Conditional Access) is required.') }
    }

    $roleNames = @{}
    foreach ($r in $pim.roles) {
        if ($r.templateId -notmatch $guid) { $issues.Add("Role '$($r.name)': templateId is not a GUID.") }
        if (-not $pim.tiers.ContainsKey([string]$r.tier)) { $issues.Add("Role '$($r.name)': tier $($r.tier) is not defined.") }
        if ($roleNames.ContainsKey($r.name)) { $issues.Add("Role '$($r.name)' is listed twice.") }
        $roleNames[$r.name] = $r
    }

    foreach ($a in $Config.Eligibility.assignments) {
        if (-not $roleNames.ContainsKey($a.role)) { $issues.Add("Eligibility for unknown role '$($a.role)'."); continue }
        $limit = $pim.tiers[[string]$roleNames[$a.role].tier].eligibilityMaxDays
        if ($a.days -gt $limit) { $issues.Add("Eligibility '$($a.role)' -> '$($a.group)': $($a.days) days exceeds tier limit $limit.") }
        if ($a.group -in $pim.breakGlassAccounts) { $issues.Add("Break-glass account used as an eligibility principal for '$($a.role)'.") }
    }

    $catalogs = @($Config.Packages.catalogs | ForEach-Object { $_.name })
    foreach ($p in $Config.Packages.packages) {
        $pol = $p.policy
        if ($p.catalog -notin $catalogs) { $issues.Add("Package '$($p.name)': catalog '$($p.catalog)' is not defined.") }
        if ($pol.expirationDays -gt 365) { $issues.Add("Package '$($p.name)': assignments must expire within 365 days.") }
        if (-not $pol.review.enabled) { $issues.Add("Package '$($p.name)': a recurring access review is required.") }
        if ($pol.review.onNoResponse -ne 'removeAccess') { $issues.Add("Package '$($p.name)': access must be removed when reviewers do not respond.") }
        if ($p.privileged -and @($pol.approval.stages).Count -lt 2) { $issues.Add("Package '$($p.name)': privileged packages need two approval stages.") }
        if ($pol.requestors.type -eq 'allExternal') {
            if ($pol.expirationDays -gt 90) { $issues.Add("Package '$($p.name)': guest access must expire within 90 days.") }
            if ($pol.review.frequency -ne 'monthly') { $issues.Add("Package '$($p.name)': guest access must be reviewed monthly.") }
        }
    }

    foreach ($r in $Config.Reviews.reviews) {
        if (-not $r.autoApply) { $issues.Add("Review '$($r.name)': decisions must be applied automatically.") }
        if ($r.defaultDecision -notin @('Deny', 'None')) { $issues.Add("Review '$($r.name)': default decision must be Deny or None, never Approve.") }
        if ($r.type -eq 'role') {
            foreach ($rn in $r.roles) { if (-not $roleNames.ContainsKey($rn)) { $issues.Add("Review '$($r.name)': unknown role '$rn'.") } }
        }
        if ($r.type -eq 'guests' -and $r.frequency -ne 'monthly') { $issues.Add("Review '$($r.name)': guest reviews must be monthly.") }
    }
    $reviewed = @($Config.Reviews.reviews | Where-Object { $_.type -eq 'role' } | ForEach-Object { $_.roles }) | Sort-Object -Unique
    foreach ($rn in $roleNames.Keys) {
        if ($rn -notin $reviewed) { $issues.Add("Role '$rn' has no recurring access review.") }
    }
    return , $issues.ToArray()
}

# ------------------------------------------------------------------------------------------ builders

function New-PimTarget {
    param([ValidateSet('EndUser', 'Admin')][string]$Caller, [ValidateSet('Assignment', 'Eligibility')][string]$Level)
    @{ caller = $Caller; operations = @('All'); level = $Level; inheritableSettings = @(); enforcedSettings = @() }
}

function ConvertTo-PimPolicyRuleSet {
    <#
    .SYNOPSIS
        Builds the unifiedRoleManagementPolicyRule PATCH bodies for one tier.
        Rule IDs are the fixed IDs Entra uses in every directory-role policy.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Tier,
        [string]$ApproverGroupId
    )
    $rules = [System.Collections.Generic.List[hashtable]]::new()

    $rules.Add(@{
            '@odata.type'        = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'
            id                   = 'Expiration_EndUser_Assignment'
            isExpirationRequired = $true
            maximumDuration      = "PT$($Tier.maxActivationHours)H"
            target               = New-PimTarget -Caller EndUser -Level Assignment
        })

    $enabled = @()
    if ($Tier.requireMfa -and -not $Tier.authenticationContext) { $enabled += 'MultiFactorAuthentication' }
    if ($Tier.requireJustification) { $enabled += 'Justification' }
    if ($Tier.requireTicket) { $enabled += 'Ticketing' }
    $rules.Add(@{
            '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule'
            id            = 'Enablement_EndUser_Assignment'
            enabledRules  = $enabled
            target        = New-PimTarget -Caller EndUser -Level Assignment
        })

    $rules.Add(@{
            '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule'
            id            = 'AuthenticationContext_EndUser_Assignment'
            isEnabled     = [bool]$Tier.authenticationContext
            claimValue    = [string]$Tier.authenticationContext
            target        = New-PimTarget -Caller EndUser -Level Assignment
        })

    $stages = @()
    if ($Tier.requireApproval) {
        if (-not $ApproverGroupId) { throw 'Approval is required for this tier but no approver group ID was supplied.' }
        $stages = @(@{
                approvalStageTimeOutInDays      = 1
                isApproverJustificationRequired = $true
                escalationTimeInMinutes         = 0
                isEscalationEnabled             = $false
                primaryApprovers                = @(@{ '@odata.type' = '#microsoft.graph.groupMembers'; groupId = $ApproverGroupId })
                escalationApprovers             = @()
            })
    }
    $rules.Add(@{
            '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'
            id            = 'Approval_EndUser_Assignment'
            setting       = @{
                isApprovalRequired               = [bool]$Tier.requireApproval
                isApprovalRequiredForExtension   = $false
                isRequestorJustificationRequired = $true
                approvalMode                     = 'SingleStage'
                approvalStages                   = $stages
            }
            target        = New-PimTarget -Caller EndUser -Level Assignment
        })

    # Eligible assignments must expire; permanent ACTIVE assignments are not allowed (only break-glass).
    $rules.Add(@{
            '@odata.type'        = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'
            id                   = 'Expiration_Admin_Eligibility'
            isExpirationRequired = $true
            maximumDuration      = "P$($Tier.eligibilityMaxDays)D"
            target               = New-PimTarget -Caller Admin -Level Eligibility
        })
    $rules.Add(@{
            '@odata.type'        = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'
            id                   = 'Expiration_Admin_Assignment'
            isExpirationRequired = $true
            maximumDuration      = 'P15D'
            target               = New-PimTarget -Caller Admin -Level Assignment
        })
    return , $rules.ToArray()
}

function ConvertTo-Recurrence {
    param([ValidateSet('monthly', 'quarterly', 'semiAnnual', 'annual')][string]$Frequency, [datetime]$Start)
    $interval = @{ monthly = 1; quarterly = 3; semiAnnual = 6; annual = 12 }[$Frequency]
    @{
        pattern = @{ type = 'absoluteMonthly'; interval = $interval; dayOfMonth = $Start.Day }
        range   = @{ type = 'noEnd'; startDate = $Start.ToString('yyyy-MM-dd') }
    }
}

function ConvertTo-ApproverObject {
    param([System.Collections.IDictionary]$Stage, [hashtable]$GroupIds)
    switch ($Stage.approver) {
        'manager' { @{ '@odata.type' = '#microsoft.graph.requestorManager'; managerLevel = 1 } }
        'group' { @{ '@odata.type' = '#microsoft.graph.groupMembers'; groupId = $GroupIds[$Stage.group] } }
        default { throw "Unknown approver type '$($Stage.approver)'." }
    }
}

function ConvertTo-AssignmentPolicyBody {
    <#
    .SYNOPSIS
        Builds the accessPackageAssignmentPolicy body for one package (entitlement management v1.0 API).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Package,
        [Parameter(Mandatory)][string]$AccessPackageId,
        [Parameter(Mandatory)][hashtable]$GroupIds,
        [datetime]$ReviewStart = (Get-Date).Date.AddDays(30)
    )
    $p = $Package.policy
    $scope = switch ($p.requestors.type) {
        'specificGroup' { @{ allowedTargetScope = 'specificDirectoryUsers'; specificAllowedTargets = @(@{ '@odata.type' = '#microsoft.graph.groupMembers'; groupId = $GroupIds[$p.requestors.group] }) } }
        'allMembers' { @{ allowedTargetScope = 'allMemberUsers'; specificAllowedTargets = @() } }
        'allExternal' { @{ allowedTargetScope = 'allExternalUsers'; specificAllowedTargets = @() } }
        default { throw "Unknown requestor type '$($p.requestors.type)'." }
    }
    $stages = foreach ($s in $p.approval.stages) {
        @{
            durationBeforeAutomaticDenial   = "P$($p.approval.timeoutDays)D"
            isApproverJustificationRequired = $true
            isEscalationEnabled             = $false
            primaryApprovers                = @(ConvertTo-ApproverObject -Stage $s -GroupIds $GroupIds)
            fallbackPrimaryApprovers        = @()
        }
    }
    $reviewers = @(switch ($p.review.reviewer) {
        'manager' { @(@{ '@odata.type' = '#microsoft.graph.requestorManager'; managerLevel = 1 }) }
        'group' { @(@{ '@odata.type' = '#microsoft.graph.groupMembers'; groupId = $GroupIds[$p.review.reviewerGroup] }) }
        default { throw "Unknown reviewer type '$($p.review.reviewer)'." }
    })
    $body = @{
        displayName             = "$($Package.name) - standard policy"
        description             = 'Managed by entra-pim-governance. Do not edit in the portal.'
        allowedTargetScope      = $scope.allowedTargetScope
        specificAllowedTargets  = $scope.specificAllowedTargets
        expiration              = @{ type = 'afterDuration'; duration = "P$($p.expirationDays)D" }
        requestorSettings       = @{
            enableTargetsToSelfAddAccess     = $true
            enableTargetsToSelfUpdateAccess  = $true
            enableTargetsToSelfRemoveAccess  = $true
            allowCustomAssignmentSchedule    = $false
            enableOnBehalfRequestorsToAddAccess = $false
        }
        requestApprovalSettings = @{
            isApprovalRequiredForAdd    = $true
            isApprovalRequiredForUpdate = $true
            stages                      = @($stages)
        }
        reviewSettings          = @{
            isEnabled                       = [bool]$p.review.enabled
            expirationBehavior              = $p.review.onNoResponse
            isRecommendationEnabled         = $true
            isReviewerJustificationRequired = $true
            isSelfReview                    = $false
            schedule                        = @{
                startDateTime = $ReviewStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
                expiration    = @{ type = 'afterDuration'; duration = 'P14D' }
                recurrence    = ConvertTo-Recurrence -Frequency $p.review.frequency -Start $ReviewStart
            }
            primaryReviewers                = $reviewers
            fallbackReviewers               = @()
        }
        accessPackage           = @{ id = $AccessPackageId }
    }
    return $body
}

function ConvertTo-AccessReviewBody {
    <#
    .SYNOPSIS
        Builds an accessReviewScheduleDefinition body for a role, group or guest review.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Review,
        [hashtable]$RoleIds = @{},
        [hashtable]$GroupIds = @{},
        [datetime]$Start = (Get-Date).Date.AddDays(7)
    )
    $q = { param($query) @{ '@odata.type' = '#microsoft.graph.accessReviewQueryScope'; query = $query; queryType = 'MicrosoftGraph' } }

    $body = @{
        displayName             = $Review.name
        descriptionForAdmins    = 'Managed by entra-pim-governance.'
        descriptionForReviewers = 'Approve only people who still need this access for their current job. Unanswered items are removed.'
        settings                = @{
            mailNotificationsEnabled        = $true
            reminderNotificationsEnabled    = $true
            justificationRequiredOnApproval = [bool]$Review.justificationRequired
            defaultDecisionEnabled          = $true
            defaultDecision                 = $Review.defaultDecision
            instanceDurationInDays          = $Review.durationDays
            autoApplyDecisionsEnabled       = [bool]$Review.autoApply
            recommendationsEnabled          = $true
            recurrence                      = ConvertTo-Recurrence -Frequency $Review.frequency -Start $Start
        }
    }

    switch ($Review.type) {
        'role' {
            $body.scope = @{
                '@odata.type'   = '#microsoft.graph.principalResourceMembershipsScope'
                principalScopes = @( (& $q '/users'), (& $q '/groups') )
                resourceScopes  = @($Review.roles | ForEach-Object { & $q "/roleManagement/directory/roleDefinitions/$($RoleIds[$_])" })
            }
        }
        'group' {
            # One definition per group keeps decisions and reports separate; the deploy script loops over groups.
            $gid = $GroupIds[$Review.groups[0]]
            $body.scope = & $q "/groups/$gid/transitiveMembers"
        }
        'guests' {
            $body.instanceEnumerationScope = & $q "/groups?`$filter=(groupTypes/any(c:c+eq+'Unified'))"
            $body.scope = & $q "./members/microsoft.graph.user/?`$count=true&`$filter=(userType eq 'Guest')"
        }
        default { throw "Unknown review type '$($Review.type)'." }
    }

    $body.reviewers = @(switch ($Review.reviewers.type) {
        'group' { @(@{ query = "/groups/$($GroupIds[$Review.reviewers.group])/transitiveMembers"; queryType = 'MicrosoftGraph' }) }
        'groupOwners' { @(@{ query = './owners'; queryType = 'MicrosoftGraph' }) }
        'managers' { @(@{ query = './manager'; queryType = 'MicrosoftGraph'; queryRoot = 'decisions' }) }
        default { throw "Unknown reviewer type '$($Review.reviewers.type)'." }
    })
    return $body
}

# ------------------------------------------------------------------------------------------ Graph helpers

function Invoke-GovGraph {
    [CmdletBinding()]
    param(
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')][string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Uri,
        $Body
    )
    $params = @{ Method = $Method; Uri = $Uri; OutputType = 'Hashtable' }
    if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 20); $params.ContentType = 'application/json' }
    Invoke-MgGraphRequest @params
}

function Get-GovGraphAll {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri)
    $next = $Uri
    while ($next) {
        $page = Invoke-GovGraph -Uri $next
        foreach ($item in $page.value) { $item }
        $next = $page['@odata.nextLink']
    }
}

function Resolve-GovGroupId {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Name)
    $map = @{}
    foreach ($n in ($Name | Sort-Object -Unique)) {
        $escaped = $n.Replace("'", "''")
        $found = @(Get-GovGraphAll -Uri "/v1.0/groups?`$filter=displayName eq '$escaped'&`$select=id,displayName")
        if ($found.Count -ne 1) { throw "Expected exactly one group named '$n', found $($found.Count)." }
        $map[$n] = $found[0].id
    }
    return $map
}

Export-ModuleMember -Function Read-GovConfig, Test-GovernanceConfig, ConvertTo-PimPolicyRuleSet, ConvertTo-AssignmentPolicyBody,
ConvertTo-AccessReviewBody, ConvertTo-Recurrence, Invoke-GovGraph, Get-GovGraphAll, Resolve-GovGroupId
