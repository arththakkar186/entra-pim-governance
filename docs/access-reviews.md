# Access Reviews

| Review | Scope | Reviewers | Frequency | Duration | No response |
|---|---|---|---|---:|---|
| Tier 0 role eligibility | Users and groups eligible or active in the 5 Tier 0 roles | Tier 0 approver group | Quarterly | 14 d | Deny (removed) |
| Tier 1 and 2 role eligibility | The 8 Tier 1/2 roles | Tier 1 approver group | Quarterly | 14 d | Deny |
| Finance application groups | Transitive members, one review per group | Group owners | Quarterly | 14 d | Deny |
| Guests in Microsoft 365 groups | Every M365 group, guest members only | Group owners | Monthly | 7 d | Deny |
| (In access packages) | Package assignments | As set per package | Monthly to semi-annual | 14 d | Remove access |

## Settings applied to every review

- **Default decision Deny, applied automatically.** An unanswered review removes access, so nobody can pass it by doing nothing.
- **Justification required** on approval.
- **Recommendations on.** Entra suggests *deny* for people who have not signed in for 30 days, which speeds up reviews.
- **Reminders on**, and reviewers are mailed at the start and mid-way.

## Evidence

Each completed review instance keeps the decisions, reviewer, justification and time. For audits, export
`/identityGovernance/accessReviews/definitions/{id}/instances/{id}/decisions` per quarter and keep the export with the
workpaper. That export is the population for an ITGC "periodic access review" control.

## Reviewer guidance (shown in each review)

> Approve only people who still need this access for their current job. Unanswered items are removed.
