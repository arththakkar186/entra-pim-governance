#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
# Offline tests: config rules and Graph request bodies. No tenant connection needed.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'modules' 'EntraGovernance' 'EntraGovernance.psm1') -Force
    $script:ConfigPath = Join-Path $PSScriptRoot '..' 'config'
    function Get-FreshConfig { Read-GovConfig -ConfigPath $script:ConfigPath }
}

Describe 'Committed configuration' {
    It 'passes every governance rule' {
        Test-GovernanceConfig -Config (Get-FreshConfig) | Should -BeNullOrEmpty
    }
    It 'contains no tenant-specific IDs or real domains' {
        $raw = Get-ChildItem (Join-Path $script:ConfigPath '*.json') | Get-Content -Raw
        $raw | Should -Not -Match 'onmicrosoft\.com'
        ($raw | Select-String -Pattern '@[a-z0-9.-]+' -AllMatches).Matches.Value |
            ForEach-Object { $_ | Should -Be '@contoso.example' }
    }
    It 'gives every role an eligibility rule' {
        $c = Get-FreshConfig
        $eligible = $c.Eligibility.assignments | ForEach-Object { $_.role }
        foreach ($r in $c.Pim.roles) { $r.name | Should -BeIn $eligible -Because 'a managed role with no eligible group invites standing access' }
    }
}

Describe 'Governance rules catch bad config' {
    It 'rejects <case>' -ForEach @(
        @{ case = 'tier 0 without approval';        mutate = { param($c) $c.Pim.tiers['0'].requireApproval = $false };      expect = 'Tier 0: activation must require approval' }
        @{ case = 'tier 0 longer than 4 hours';     mutate = { param($c) $c.Pim.tiers['0'].maxActivationHours = 6 };         expect = 'Tier 0: maxActivationHours must be 4' }
        @{ case = 'tier 0 without auth context';    mutate = { param($c) $c.Pim.tiers['0'].authenticationContext = $null }; expect = 'authentication context' }
        @{ case = 'activation over 8 hours';        mutate = { param($c) $c.Pim.tiers['1'].maxActivationHours = 12 };        expect = 'exceeds 8' }
        @{ case = 'no MFA and no auth context';     mutate = { param($c) $c.Pim.tiers['2'].requireMfa = $false };            expect = 'Tier 2: activation needs MFA' }
        @{ case = 'no justification';               mutate = { param($c) $c.Pim.tiers['1'].requireJustification = $false };  expect = 'justification must be required' }
        @{ case = 'one break-glass account';        mutate = { param($c) $c.Pim.breakGlassAccounts = @('bg-admin-01@contoso.example') }; expect = 'two break-glass' }
        @{ case = 'eligibility over tier limit';    mutate = { param($c) $c.Eligibility.assignments[0].days = 400 };          expect = 'exceeds tier limit' }
        @{ case = 'package without expiry limit';   mutate = { param($c) $c.Packages.packages[0].policy.expirationDays = 730 }; expect = 'expire within 365' }
        @{ case = 'privileged single-stage';        mutate = { param($c) $c.Packages.packages[0].policy.approval.stages = @(@{ approver = 'manager' }) }; expect = 'two approval stages' }
        @{ case = 'review keeps access on silence'; mutate = { param($c) $c.Packages.packages[2].policy.review.onNoResponse = 'keepAccess' }; expect = 'removed when reviewers do not respond' }
        @{ case = 'guest package 180 days';         mutate = { param($c) $c.Packages.packages[3].policy.expirationDays = 180 }; expect = 'guest access must expire within 90' }
        @{ case = 'default decision Approve';       mutate = { param($c) $c.Reviews.reviews[0].defaultDecision = 'Approve' }; expect = 'never Approve' }
        @{ case = 'review not auto-applied';        mutate = { param($c) $c.Reviews.reviews[1].autoApply = $false };          expect = 'applied automatically' }
        @{ case = 'role missing from reviews';      mutate = { param($c) $c.Reviews.reviews[0].roles = @('Global Administrator') }; expect = 'has no recurring access review' }
        @{ case = 'bad template id';                mutate = { param($c) $c.Pim.roles[0].templateId = 'not-a-guid' };       expect = 'not a GUID' }
    ) {
        $c = Get-FreshConfig
        & $mutate $c
        (Test-GovernanceConfig -Config $c) -join "`n" | Should -Match ([regex]::Escape($expect))
    }
}

Describe 'ConvertTo-PimPolicyRuleSet' {
    BeforeAll { $script:c = Get-FreshConfig }

    It 'tier 0: approval by group, auth context, 2h, ticket + justification' {
        $rules = ConvertTo-PimPolicyRuleSet -Tier $c.Pim.tiers['0'] -ApproverGroupId '11111111-1111-1111-1111-111111111111'
        $byId = @{}; $rules | ForEach-Object { $byId[$_.id] = $_ }
        $byId['Expiration_EndUser_Assignment'].maximumDuration | Should -Be 'PT2H'
        $byId['Approval_EndUser_Assignment'].setting.isApprovalRequired | Should -BeTrue
        $byId['Approval_EndUser_Assignment'].setting.approvalStages[0].primaryApprovers[0].groupId | Should -Be '11111111-1111-1111-1111-111111111111'
        $byId['AuthenticationContext_EndUser_Assignment'].isEnabled | Should -BeTrue
        $byId['AuthenticationContext_EndUser_Assignment'].claimValue | Should -Be 'c1'
        ($byId['Enablement_EndUser_Assignment'].enabledRules -join ',') | Should -Be 'Justification,Ticketing'
        $byId['Expiration_Admin_Eligibility'].maximumDuration | Should -Be 'P180D'
    }
    It 'tier 1: MFA, no approval, 8h' {
        $rules = ConvertTo-PimPolicyRuleSet -Tier $c.Pim.tiers['1']
        ($rules | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' }).enabledRules | Should -Contain 'MultiFactorAuthentication'
        ($rules | Where-Object { $_.id -eq 'Approval_EndUser_Assignment' }).setting.isApprovalRequired | Should -BeFalse
        ($rules | Where-Object { $_.id -eq 'Expiration_EndUser_Assignment' }).maximumDuration | Should -Be 'PT8H'
    }
    It 'throws when approval is required but no approver group is given' {
        { ConvertTo-PimPolicyRuleSet -Tier $c.Pim.tiers['0'] } | Should -Throw '*approver group*'
    }
    It 'serialises approvalStages as a JSON array' {
        $json = ConvertTo-PimPolicyRuleSet -Tier $c.Pim.tiers['0'] -ApproverGroupId 'g' | ConvertTo-Json -Depth 20
        $json | Should -Match '"approvalStages":\s*\['
    }
}

Describe 'ConvertTo-AssignmentPolicyBody' {
    BeforeAll {
        $script:c = Get-FreshConfig
        $script:ids = @{ 'IT-Endpoint-Team' = 'g-req'; 'PIM-Approvers-Tier1' = 'g-appr'; 'Partner-Sponsors' = 'g-spon' }
    }
    It 'privileged package: two stages (manager, then group), 180-day expiry, quarterly review removes access' {
        $b = ConvertTo-AssignmentPolicyBody -Package $c.Packages.packages[0] -AccessPackageId 'ap1' -GroupIds $ids -ReviewStart ([datetime]'2026-12-01')
        $b.allowedTargetScope | Should -Be 'specificDirectoryUsers'
        $b.specificAllowedTargets[0].groupId | Should -Be 'g-req'
        $b.requestApprovalSettings.stages.Count | Should -Be 2
        $b.requestApprovalSettings.stages[0].primaryApprovers[0].'@odata.type' | Should -Be '#microsoft.graph.requestorManager'
        $b.requestApprovalSettings.stages[1].primaryApprovers[0].groupId | Should -Be 'g-appr'
        $b.expiration.duration | Should -Be 'P180D'
        $b.reviewSettings.expirationBehavior | Should -Be 'removeAccess'
        $b.reviewSettings.isSelfReview | Should -BeFalse
        $b.reviewSettings.schedule.recurrence.pattern.interval | Should -Be 3
    }
    It 'guest package targets all external users, monthly' {
        $b = ConvertTo-AssignmentPolicyBody -Package $c.Packages.packages[3] -AccessPackageId 'ap4' -GroupIds $ids
        $b.allowedTargetScope | Should -Be 'allExternalUsers'
        $b.reviewSettings.schedule.recurrence.pattern.interval | Should -Be 1
    }
    It 'serialises single reviewers and single stages as arrays' {
        $json = ConvertTo-AssignmentPolicyBody -Package $c.Packages.packages[2] -AccessPackageId 'ap3' -GroupIds $ids | ConvertTo-Json -Depth 20
        $json | Should -Match '"primaryReviewers":\s*\['
        $json | Should -Match '"stages":\s*\['
    }
}

Describe 'ConvertTo-AccessReviewBody' {
    BeforeAll {
        $script:c = Get-FreshConfig
        $script:roleIds = @{}; $c.Pim.roles | ForEach-Object { $roleIds[$_.name] = $_.templateId }
        $script:groupIds = @{ 'PIM-Approvers-Tier0' = 'g0'; 'PIM-Approvers-Tier1' = 'g1'; 'APP-ERP-AP-Users' = 'gap'; 'APP-ERP-GL-Posting' = 'ggl' }
    }
    It 'role review scopes every listed role and defaults to Deny with auto-apply' {
        $b = ConvertTo-AccessReviewBody -Review $c.Reviews.reviews[0] -RoleIds $roleIds -GroupIds $groupIds
        $b.scope.resourceScopes.Count | Should -Be 5
        $b.scope.resourceScopes[0].query | Should -Be '/roleManagement/directory/roleDefinitions/62e90394-69f5-4237-9190-012177145e10'
        $b.settings.defaultDecision | Should -Be 'Deny'
        $b.settings.autoApplyDecisionsEnabled | Should -BeTrue
        $b.reviewers[0].query | Should -Be '/groups/g0/transitiveMembers'
    }
    It 'group review targets transitive members and is reviewed by owners' {
        $r = $c.Reviews.reviews[2].Clone(); $r.groups = @('APP-ERP-GL-Posting')
        $b = ConvertTo-AccessReviewBody -Review $r -GroupIds $groupIds
        $b.scope.query | Should -Be '/groups/ggl/transitiveMembers'
        $b.reviewers[0].query | Should -Be './owners'
    }
    It 'guest review enumerates Microsoft 365 groups and filters guests' {
        $b = ConvertTo-AccessReviewBody -Review $c.Reviews.reviews[3]
        $b.instanceEnumerationScope.query | Should -Match "groupTypes/any"
        $b.scope.query | Should -Match "userType eq 'Guest'"
        $b.settings.recurrence.pattern.interval | Should -Be 1
    }
    It 'serialises a single reviewer as an array' {
        ConvertTo-AccessReviewBody -Review $c.Reviews.reviews[3] | ConvertTo-Json -Depth 20 | Should -Match '"reviewers":\s*\['
    }
}
