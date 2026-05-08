# Issue 212 VISS31 Execution Plan

This document tracks the implementation as a sequence of small sub-branches and PRs,
all based on `feature/issue-212-viss31` and published on the `mikehaller` fork.

## Workflow Contract

1. Create one GitHub issue per step in `mikehaller/kuksa-databroker`.
2. Create one dedicated sub-branch per step from `feature/issue-212-viss31`.
3. Open PR from sub-branch into `feature/issue-212-viss31` (not `main`).
4. Review, adjust, and merge step PR.
5. Repeat with the next step branch from updated `feature/issue-212-viss31`.

This preserves rationale and progress as issues + PRs on the fork while keeping each
review scope intentionally small.

## Branch Naming Convention

- Parent integration branch: `feature/issue-212-viss31`
- Step branch format: `feature/issue-212-viss31-sXX-<short-topic>`

Examples:

- `feature/issue-212-viss31-s01-doc-scope`
- `feature/issue-212-viss31-s02-test-harness`
- `feature/issue-212-viss31-s03-ci-smoke`

## Step Tracker

| Step | Topic | Issue | Branch | PR | Status |
|------|-------|-------|--------|----|--------|
| S01 | Docs: clarify VISS scope and current support | #2 | `feature/issue-212-viss31-s01-doc-scope` | TBD | In progress |
| S02 | Test harness: planned/mock transport markers and explicit gRPC skip | #3 | `feature/issue-212-viss31-s02-test-harness` | TBD | In progress |
| S03 | CI: lightweight VISS collection/smoke execution | TBD | `feature/issue-212-viss31-s03-ci-smoke` | TBD | Planned |
| S04 | Implement dynamic metadata + server capabilities behavior | TBD | `feature/issue-212-viss31-s04-dynamic-metadata` | TBD | Planned |
| S05 | History filter behavior: deterministic contract | TBD | `feature/issue-212-viss31-s05-history-filter` | TBD | Planned |
| S06 | Subscription filters: range/change | TBD | `feature/issue-212-viss31-s06-range-change` | TBD | Planned |
| S07 | Subscription stream correctness (batch handling) | TBD | `feature/issue-212-viss31-s07-subscription-batch` | TBD | Planned |
| S08 | Curvelog support or formal defer path | TBD | `feature/issue-212-viss31-s08-curvelog` | TBD | Planned |
| S09 | Transport scope decision and alignment (HTTP/MQTT/V3) | TBD | `feature/issue-212-viss31-s09-transport-scope` | TBD | Planned |

## GitHub Issue Template (CLI)

Use this for each step issue on the fork:

```sh
gh issue create \
  --repo mikehaller/kuksa-databroker \
  --title "[Issue 212][S01] Docs: clarify VISS scope" \
  --body "## Goal
Clarify current VISS implementation scope to avoid overclaiming support.

## Scope
- Update README scope statement
- Update doc/protocol wording
- Add implementation status to integration_test/viss/readme.md

## Out of Scope
- No runtime behavior changes

## Acceptance
- Documentation reflects current production support accurately
- Reviewable in one small PR"
```

## Per-Step Branch + PR Commands

```sh
# Ensure parent branch is current
git checkout feature/issue-212-viss31
git pull --ff-only origin feature/issue-212-viss31

# Create step branch
git checkout -b feature/issue-212-viss31-s01-doc-scope

# ...make only the step changes...

git add <files>
git commit -m "docs(viss): clarify current support scope [S01]"
git push -u origin feature/issue-212-viss31-s01-doc-scope

gh pr create \
  --repo mikehaller/kuksa-databroker \
  --base feature/issue-212-viss31 \
  --head feature/issue-212-viss31-s01-doc-scope \
  --title "[Issue 212][S01] Clarify VISS support scope in docs" \
  --body "Closes #<fork-issue-number>"
```

## Merge Strategy

- Merge each step PR into `feature/issue-212-viss31` only after review.
- Rebase or recreate the next step branch from the updated parent branch.
- Keep each PR single-purpose; no unrelated edits.
