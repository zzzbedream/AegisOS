---
name: ship-ticket
description: Ship one Exponential **Ticket** — commit any leftover work, run pre-ship checks, open (or extend) a PR, link the PR back to the Ticket, transition the Ticket to `QA`, then wait for the repo's automated reviewer and apply its findings. The back-end bookend to `/start-ticket`. Runs in **new PR mode** for the first Ticket on a branch and **stack mode** for subsequent Tickets on the same branch. Merges only when asked (`--merge`). Use when work for a Ticket is ready for review.
---

# Ship Ticket

Ship exactly one Ticket per invocation. To put multiple Tickets on one PR, stay on the branch and run `/ship-ticket` again after `/start-ticket`-ing the next Ticket — same-branch reuse triggers **stack mode** automatically. See [ADR-0004](../../../.agents/adr/0004-one-ticket-per-ship-stacking-via-branch.md).

## Usage

```
/ship-ticket [<cuid-or-shortId>] [--skip-checks] [--no-review] [--merge]
```

- `<cuid-or-shortId>` (optional): explicit Ticket. Overrides auto-detection.
- `--skip-checks`: bypass pre-ship checks. PR is opened as **draft** to signal incomplete verification.
- `--no-review`: skip the review + autofix loop (step 8). The PR is left exactly as pushed.
- `--merge`: after the review loop and CI, squash-merge the PR (step 9). **Off by default** — shipping a Ticket normally means putting it *in review*, not on the Trunk.

## Prerequisites

- Inside a git repo (`git rev-parse --show-toplevel`).
- `gh` authenticated (`gh auth status`).
- `exponential auth status` ok.
- `docs/agents/git-flow.md` exists (run `/setup-git-flow` first if not). Parse its front-matter to read `featureBase`.

## Process

### 1. Resolve the Ticket

Auto-detect order — first hit wins:

1. **Explicit arg** — `<cuid-or-shortId>` passed in.
2. **Marker file** — `.exponential/current-ticket` (one CUID, no newline). Skip if the file is missing or empty.
3. **Branch lookup** — `exponential tickets list --branch <current-branch> --json`. **Filter out** any ticket already in `QA` (those are already shipped and stacked onto this branch — we want the still-`IN_PROGRESS` one).

If multiple Tickets match after filtering, surface them and ask the user to disambiguate. If none match, error: tell the user to pass an explicit arg or run `/start-ticket` first.

Fetch the full Ticket via `exponential tickets get <cuid> --json` and capture: `id`, `shortId`, `title`, `body`, `type`, `status`, `prUrl`, `branchName`.

### 2. Pre-ship checks (Node-only first cut)

If `--skip-checks` is set, **skip this section entirely** and remember to open the PR as draft.

Discover from `package.json` scripts (top-level only, no monorepo traversal for now):

```bash
node -e "const s=require('./package.json').scripts||{}; \
  for (const k of ['typecheck','test','lint']) if (s[k]) console.log(k)"
```

For each script that exists, run it in this order: `typecheck`, then `test`, then `lint`. Stop on the first failure and refuse to push. Tell the user:

- which check failed
- the failing output (last ~30 lines)
- that they can either fix and re-run, or re-invoke with `--skip-checks` to open as draft

If `package.json` has none of those scripts, skip silently — don't invent checks.

> Note: other ecosystems (Cargo, pyproject, gradle) are out of scope for this first cut. Extend later as needed.

### 3. Commit handling (three states)

Run `git status --porcelain` and `git rev-list --count <featureBase>..HEAD` to classify:

**State A — working tree changes + zero commits ahead of `featureBase`:**

Stage everything and commit:

```bash
git add -A
git commit -m "$(cat <<'EOF'
<type>(<scope>): <title>

Refs: <shortId>
Exponential-Ticket: <cuid>
EOF
)"
```

- `<type>` derives from Ticket type: `FEATURE` → `feat`, `BUG` → `fix`, `CHORE` → `chore`, `IMPROVEMENT` → `refactor`, `SPIKE` → `chore`, `RESEARCH` → `docs`.
- `<scope>` is optional. Omit it if you don't know — `feat: <title>` is fine.
- Trailers: `Refs` is human-readable, `Exponential-Ticket` is machine-readable. The trailers are decoration only — see [ADR-0003](../../../.agents/adr/0003-pr-url-primary-trailer-fallback.md). PR-URL linkage is the source of truth.

**State B — clean tree + N>0 commits ahead:**

Don't create a new commit. The work is already committed; just push.

**State C — mixed (some commits ahead AND working tree changes):**

Commit only the leftovers. Use the same trailers. Existing commits ride along unchanged — don't rewrite history.

### 4. Pre-ship checks, take two

If commits were created in step 3, **re-run** the pre-ship checks (step 2) after the commit, before the push. Reason: a failing typecheck in the new commit shouldn't ship.

### 5. Push

```bash
git push -u origin HEAD
```

If push fails (e.g. remote has commits we don't), surface the failure and stop. Don't force-push.

### 6. PR handling

Check for an existing open PR on this branch:

```bash
gh pr view --json url,body,isDraft,baseRefName 2>/dev/null
```

**Stack mode** (PR exists):

- Append a line to the PR body: `Ships: <shortId>` (only if not already present).
- Do not change the PR title (the first Ticket named it).
- Do not change draft state.
- Update the PR body via `gh pr edit --body "<new-body>"`.

**New PR mode** (no existing PR):

- Read `featureBase` from `docs/agents/git-flow.md` front-matter. Default to `main` if the file is missing (and warn the user that `/setup-git-flow` should be run).
- Title: `<type>: <title>` (from the same `<type>` derivation as step 3).
- Body template:

  ````markdown
  ## What

  <ticket.body up through the first acceptance-criteria block; if there are no headings, use the full body>

  ## Acceptance criteria

  - [ ] <criterion 1>
  - [ ] <criterion 2>

  ---

  Ships: <shortId>

  [View in Exponential](<exponential-ticket-url-if-known>)
  ````

  - The acceptance-criteria list comes from parsing `- [ ]` lines under the Ticket's "Acceptance criteria" heading. If the Ticket body doesn't have one, drop the section.
  - The Exponential URL: if `exponential` config exposes a base URL (e.g. `https://app.exponential.im`), build `<base>/tickets/<cuid>`. If unknown, omit the link.

- Open ready-for-review unless `--skip-checks` was used:

  ```bash
  gh pr create --base "<featureBase>" --title "<title>" --body "<body>" [--draft]
  ```

  Capture the URL from stdout.

### 7. Link the Ticket back

Always run, both modes:

```bash
exponential tickets update --id <cuid> \
  --pr "<pr-url>" \
  --branch "<current-branch>" \
  --status QA
```

`--branch` is a no-op if it's already set to the current branch, but harmless. `--pr` is what powers the GitHub Action's `findByPrUrl` lookup at merge time.

### 8. Review + autofix loop

Skip entirely if `--no-review` or `--skip-checks` was passed.

The Ticket is already in `QA` and linked by now — that bookkeeping is deliberately done *first*, so a reviewer that hangs or a fix that fails can't leave the Ticket stranded in `IN_PROGRESS`. This step is best-effort polish on top.

Run the loop exactly as [`/ship-this` step 7](../ship-this/SKILL.md#7-review--autofix-loop) documents it: probe for a reviewer (PR-Agent → CodeRabbit → local `/pr-review`), wait on the head SHA in a **background** job rather than polling inline, apply the findings with judgement, commit per finding, push. Two rounds maximum.

Two things specific to shipping a Ticket:

- **Stack mode.** The PR may carry other Tickets' commits. The reviewer reviews the whole PR, so it will surface findings in code this invocation didn't touch. Fix them anyway — they're going to the Trunk on this PR — but attribute them in your report so it's clear which Ticket they belonged to.
- **Fix commits don't need Ticket trailers.** They're follow-ups to commits that already carry them. `fix: <one-line>` is enough; PR-URL linkage is the source of truth ([ADR-0003](../../../.agents/adr/0003-pr-url-primary-trailer-fallback.md)).

If the loop fails at any point, say so and carry on to step 10 — the Ticket is shipped either way.

### 9. Merge (only with `--merge`)

Without `--merge`, skip this — stop at "shipped, in review". That's the default because **Ship** and **merge** are different events: shipping puts the work in review, merging puts it on the Trunk, and the `QA → DONE` promotion is the merge hook's job, not this skill's.

With `--merge`, wait for CI and squash-merge:

```bash
gh pr checks --watch --fail-fast     # background job — CI outlasts a foreground call
gh pr merge --squash --delete-branch
```

- Any check red → surface the failing check and log link, **don't merge**, and leave the Ticket in `QA`.
- Branch protection blocking on required reviewers → `gh pr merge --squash --auto --delete-branch` instead, and tell the user the merge is *queued*, not done.
- **Stack mode + `--merge` deserves a pause.** Merging lands every Ticket on the PR, not just this one. Confirm with the user via `AskUserQuestion` before merging a stacked PR, naming the other Tickets that will go with it.
- Don't transition the Ticket to `DONE` by hand. The merge hook scaffolded by `/setup-merge-hook` does that on merge into the deploy trigger; doing it here would double-write and mask a broken hook.

### 10. Clear the marker

On success only:

```bash
rm -f .exponential/current-ticket
```

If anything in steps 5–7 failed, **leave the marker** so the user can re-invoke `/ship-ticket` cleanly. A failure in step 8 or 9 does *not* hold the marker — the Ticket shipped; re-running `/ship-ticket` wouldn't retry a review.

### 11. Report

Print:

- PR URL (clickable)
- Mode (new PR vs stack)
- Ticket status transition (`IN_PROGRESS → QA`)
- Which reviewer ran, how many findings it raised, which you applied and which you skipped (with the reason) — or that the loop was skipped
- Final state: `in review` / `merged` / `auto-merge queued` / `merge blocked by <check>`
- Reminder: once the PR merges into the **deploy trigger**, the Action scaffolded by `/setup-merge-hook` will auto-promote to `DONE`. If `/setup-merge-hook` hasn't been run, prompt the user.

### 12. Hand off to `/cleanup`

Only when the final state is `merged` — i.e. `--merge` was passed and it went through. Then run the `/cleanup` skill: it tears down the worktree (or hands back the one command to do it), confirms the Ticket reached `DONE` — promoting it if the merge hook didn't — and closes with the **all-clear**, the explicit statement of whether anything is still in flight and therefore whether this tab can be closed. Don't write that verdict here; `/cleanup` owns it, and it is only trustworthy because it derives from evidence that skill gathers itself.

In the default no-`--merge` case, do the opposite: state plainly that the work is **in review, not done** — the Ticket sits in `QA`, the worktree stays, and the next step is the PR merging. Never leave a shipped-but-unmerged Ticket reading as finished.

## Failure modes

- **Pre-ship check failure** — refuse to push. The user can fix and re-invoke or pass `--skip-checks`.
- **No Ticket detected** — explicit arg, marker, and branch lookup all empty. Refuse with guidance.
- **Branch-lookup ambiguity** — multiple non-`QA` Tickets share the branch. Ask the user.
- **PR exists in draft + this invocation has `--skip-checks`** — leave it draft.
- **PR exists ready + this invocation has `--skip-checks`** — leave it ready; don't downgrade.
- **`docs/agents/git-flow.md` missing** — warn loudly, default to `main`, recommend `/setup-git-flow`.
- **Review loop fails or times out** — report it and continue. The Ticket is shipped and in `QA` regardless; the review is polish, not a gate.
- **`--merge` with red CI** — don't merge, leave the Ticket in `QA`, surface the failing check.

## What this skill does NOT do

- It does not unship a Ticket (no automatic `QA → IN_PROGRESS` rollback). Deferred.
- It does not clean up abandoned PRs. Deferred.
- It does not remove the worktree or delete the branch. That's `/cleanup`, invoked at step 12 once the merge is real.
- It does not promote `QA → DONE` itself — that's the GitHub Action's job, scaffolded by `/setup-merge-hook`. This holds even under `--merge`.
- It does not merge unless you pass `--merge`. Default behaviour stops at "shipped, in review".
