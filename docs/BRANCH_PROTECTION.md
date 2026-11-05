# Making the Security Check a Hard Merge Gate

The `Security Lint` workflow (`.github/workflows/security-lint.yml`) runs the
shell-injection linter and the security test suite on every push and pull
request. By default a red check only *warns* — a merge can still be forced past
it. To make it block merges, enable **branch protection** on `main`.

This is a one-time repository setting. It cannot be done from the code; it lives
in GitHub repo settings, so a repo admin has to do it.

---

## Prerequisite: the workflow must have run at least once

A status check only appears in the "required checks" picker **after GitHub has
seen it run**. So first:

1. Merge the branch that adds `.github/workflows/security-lint.yml` into `main`
   (or open a PR from it). That triggers the workflow once.
2. Confirm it appears under the repo's **Actions** tab as `Security Lint`.

Until then, the check name won't be selectable in step 2 below.

---

## Option A — GitHub web UI (classic branch protection)

1. Go to the repo on GitHub → **Settings** → **Branches**.
2. Under **Branch protection rules**, click **Add branch protection rule**
   (or **Add rule**).
3. **Branch name pattern:** `main`
4. Tick **Require a pull request before merging**
   - (optional) set **Require approvals** = 1 so changes get a human review.
   - (optional) tick **Dismiss stale pull request approvals when new commits are
     pushed**.
5. Tick **Require status checks to pass before merging**.
   - Tick **Require branches to be up to date before merging** (forces the check
     to run against the latest `main`).
   - In the search box, find and select:
     **`Shell-injection lint + security tests`**
     (that's the job's display name; the workflow itself is `Security Lint`).
6. (optional) Tick **Require conversation resolution before merging**.
7. (optional) Tick **Do not allow bypassing the above settings** so even admins
   are held to the gate.
8. Click **Create** / **Save changes**.

From now on a PR cannot be merged while the lint or the security tests are red.

---

## Option B — GitHub web UI (newer "Rulesets")

1. **Settings** → **Rules** → **Rulesets** → **New ruleset** → **New branch
   ruleset**.
2. **Ruleset name:** e.g. `main protection`. **Enforcement status:** `Active`.
3. **Target branches** → **Add target** → **Include default branch**
   (or match pattern `main`).
4. Under **Rules**, enable:
   - **Require a pull request before merging** (set approvals if you want).
   - **Require status checks to pass** → **Add checks** →
     `Shell-injection lint + security tests`.
   - (optional) **Require branches to be up to date before merging**.
5. **Create**.

---

## Option C — Command line (`gh`)

Requires admin on the repo and the GitHub CLI. Classic protection via the API:

```bash
gh api -X PUT repos/alishahid74/kali-gpt/branches/main/protection \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      { "context": "Shell-injection lint + security tests" }
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": { "required_approving_review_count": 1 },
  "restrictions": null
}
JSON
```

> Note: GitHub GraphQL is blocked from some automated sessions, but this is the
> REST endpoint and works with a normal admin token.

---

## How to verify it works

1. Open a throwaway PR that adds a deliberate violation, e.g.:
   ```python
   import subprocess
   subprocess.run(f"echo {x}", shell=True)
   ```
2. The **Security Lint** check should go red, and the **Merge** button should be
   disabled with "Required statuses must pass before merging."
3. Close the PR.

---

## What this does and doesn't cover

- **Does:** stops *new* `shell=True` + f-string sinks and test regressions from
  being merged into `main`.
- **Doesn't:** retroactively change the 54 baselined (reviewed, guarded) sites —
  those are intentionally allowed. To tighten further, migrate them and run
  `python3 scripts/lint_shell_exec.py --update-baseline` to shrink the baseline.
- **Doesn't:** run on forks' PRs with secrets, but this workflow needs no
  secrets, so fork PRs are still linted.
