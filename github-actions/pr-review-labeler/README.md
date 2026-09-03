# Pull request automation

The review labeler is copied from [wallester/monorepo at `42aff24cf293`](https://github.com/wallester/monorepo/tree/42aff24cf2936452e740304d257bf1bbf5e4f9a4/github-actions/pr-review-labeler).
Keep future changes aligned with that source. This rollout pins the GitHub Script action,
removes two legacy review labels, and skips PRs closed while a refresh was queued.

## Review labels

- Draft PRs have managed review labels removed.
- Active changes requested by a merge-eligible reviewer produce `changes required`.
- No approvals on the current head produce `ready for review`.
- Some approvals below the configured threshold produce `ready for final review`.
- Enough approvals produce `ready for merge` only when GitHub's live review decision allows it.
- Only reviewers with write, maintain, or admin permission count. Approval counts use the latest opinionated review per reviewer; dismissed reviews clear that opinion.
- Review labels are advisory. Branch protection, required checks, code owners, conflicts, and other merge rules remain authoritative.

The workflow refreshes labels on PR lifecycle and review events, daily, and through
**Actions → Pull request review labels → Run workflow**. Manual and daily runs cover
all open PRs, including existing PRs with no new activity. Fork and Dependabot review
events are refreshed by the daily/manual run because their review-event tokens are read-only.
Each run checks out the trusted default branch with persisted credentials disabled.
It never executes PR head code with label-write permissions. The install PR skips the
label step until this local action exists on the default branch.

The configured approval threshold is **3**. It reflects the inspected
default-branch protection and rulesets at rollout time; keep it aligned with policy changes.

## Stale pull requests

After merge, the daily stale workflow marks PRs after **7 inactive days** and closes
them after a further **7-day grace period**. Drafts are included. Comments or updates
reset the timer. Add `keep-open` for an exemption. Branches are never deleted.
Issues are excluded. Missing `stale` and `keep-open` labels are created automatically.
The manual stale workflow defaults to `dry_run: true`; dry runs do not create labels
or change PRs. Review-label changes can update a PR's activity timestamp once during
initial reconciliation; unchanged labels are not written again on subsequent runs.

## Validation and rollback

Run `node --test github-actions/pr-review-labeler/action.test.cjs` locally.
The `Validate PR automation` workflow runs these scenarios for changes to this automation.
The tests exercise the JavaScript embedded in `action.yml` without credentials or network.
Disable the affected workflow or revert the rollout commit to stop automation.
Closed PRs can be reopened; removed labels can be reapplied. Reverting does not reopen PRs.
