# Git Operations Guide

This guide covers the normal Git and GitHub workflow for the NOC Intelligence Fusion Center. It favors reversible, explicit commands over shortcuts that can overwrite work.

## Repository Branches

| Branch or tag | Purpose |
|---|---|
| `main` | Production/default branch. Changes here should be reviewed and deployable. |
| `architecture/monolith-to-decoupled` | Development and maintenance branch retained as a working alias. |
| `original-main` | Read-only archive of the pre-migration `main` branch. Do not develop here. |
| `v2.0.0` | Production release tag for the current baseline. |
| `pre-main-switch-2026-09-10` | Rollback tag for the pre-migration branch state. |

Start new work from an updated `main` branch:

```bash
$ git fetch origin --prune
$ git switch main
$ git pull --ff-only origin main
$ git switch -c feature/short-description
```

Do not work directly on `original-main`. It is preserved for historical comparison and recovery.

## First-Time Identity Setup

Git identity controls the author shown on commits. It is separate from GitHub authentication.

```bash
$ git config --global user.name "Your Name"
$ git config --global user.email "you@example.com"
$ git config --global --get user.name
$ git config --global --get user.email
```

Use a repository-only identity when needed by omitting `--global`:

```bash
$ git config user.name "Your Name"
$ git config user.email "you@example.com"
```

## GitHub Authentication

This repository currently uses the SSH remote `git@github.com:PrestonWest87/NOC_IFC.git`.

### SSH Authentication

Check whether an SSH key already exists:

```bash
$ ls -la ~/.ssh
```

If needed, create a key with a passphrase:

```bash
$ ssh-keygen -t ed25519 -C "you@example.com"
$ eval "$(ssh-agent -s)"
$ ssh-add ~/.ssh/id_ed25519
```

Display the public key and add it to GitHub under **Settings -> SSH and GPG keys**:

```bash
$ cat ~/.ssh/id_ed25519.pub
```

Test the connection:

```bash
$ ssh -T git@github.com
```

Never share `~/.ssh/id_ed25519`, the private key.

### HTTPS Authentication

If SSH is unavailable, change the remote to HTTPS:

```bash
$ git remote set-url origin https://github.com/PrestonWest87/NOC_IFC.git
```

GitHub does not accept account passwords for Git operations. Use a GitHub Personal Access Token when prompted for a password or use a credential manager. Never place a token in the remote URL, shell history, scripts, `.env`, or documentation.

### GitHub CLI Authentication

If the GitHub CLI is installed:

```bash
$ gh auth login
$ gh auth status
```

Select GitHub.com and choose SSH or HTTPS to match the repository remote.

## Inspect Before Changing Anything

Run these commands before switching, pulling, rebasing, merging, or deleting a branch:

```bash
$ git status -sb
$ git branch -vv
$ git remote -v
$ git log --oneline --decorate -10
$ git diff --stat
$ git diff --check
```

A clean status means there are no uncommitted tracked changes. Untracked files still require attention; use `git status --short` to see them.

## Fetching and Pulling

Fetching downloads remote references without changing current files:

```bash
$ git fetch origin
$ git fetch origin --prune
$ git branch -r
$ git log --oneline --decorate origin/main -10
```

For a synchronized branch, use fast-forward-only pulls:

```bash
$ git switch main
$ git pull --ff-only origin main
```

If the pull fails, inspect divergence instead of forcing it:

```bash
$ git fetch origin
$ git log --oneline --left-right main...origin/main
```

Do not use `git reset --hard` as a routine solution. It can permanently discard local work.

## Changing Branches

```bash
# Existing local branch
$ git switch main

# New feature branch
$ git switch -c feature/keyword-reporting

# Local branch tracking a remote branch
$ git switch --track origin/architecture/monolith-to-decoupled
```

If local edits would be overwritten, preserve meaningful work on a temporary branch:

```bash
$ git switch -c wip/save-before-switch
$ git add -A
$ git commit -m "WIP: save local changes"
```

For temporary edits, use a stash:

```bash
$ git stash push -u -m "before branch switch"
$ git switch main
$ git stash list
$ git stash pop
```

Review a stash before applying it. Applying a stash can produce conflicts.

## Creating and Publishing Work

```bash
$ git fetch origin --prune
$ git switch main
$ git pull --ff-only origin main
$ git switch -c feature/my-change
```

Review changes:

```bash
$ git status --short
$ git diff
$ git diff --check
```

Stage only intended files:

```bash
$ git add path/to/file.md
$ git add path/to/another-file.py
$ git diff --cached --stat
$ git diff --cached --check
```

Commit and publish:

```bash
$ git commit -m "Describe the change"
$ git push -u origin feature/my-change
```

Later pushes can use `git push`. Do not force-push shared branches. If an approved force push is unavoidable, use the safer lease-protected form:

```bash
$ git push --force-with-lease origin feature/my-change
```

## Updating `.gitignore`

`.gitignore` prevents files from being shown as untracked. It does not remove files that are already committed.

Add a pattern such as `local-tool-cache/` under the appropriate existing category:

```gitignore
# Local tooling output
local-tool-cache/
```

Verify the rule:

```bash
$ git check-ignore -v .local-tool-cache/example.json
$ git status --short
```

If an already tracked file should no longer be versioned, remove it from the index while keeping the local file:

```bash
$ git rm --cached path/to/local-file
$ git add .gitignore
$ git commit -m "Ignore local file"
```

Never commit `.env`, private keys, API tokens, database files, or generated secrets. If a secret was committed previously, rotate it immediately; `.gitignore` does not remove it from repository history.

## Reviewing Commits

Before committing:

```bash
$ git status --short
$ git diff --stat
$ git diff --check
$ git diff --cached --stat
$ git diff --cached --check
$ git log --oneline -10
```

After committing:

```bash
$ git show --stat --oneline HEAD
$ git status -sb
```

Never include unrelated work in a commit. If the worktree contains changes you did not make, stop and review them before staging.

## Handling Merge Conflicts

Preserve the current position before resolving conflicts:

```bash
$ git status -sb
$ git branch backup/before-conflict-resolution
```

Resolve the conflict markers in each file, then stage and commit the result:

```bash
$ git add path/to/resolved-file
$ git diff --cached --check
$ git commit
```

Abort an operation when the result is not safe:

```bash
$ git rebase --abort
$ git merge --abort
```

Do not delete conflict backups until the final result has been verified.

## Recovery and Rollback

Find recent branch positions:

```bash
$ git reflog --date=local
```

Create a recovery branch before investigating a lost commit:

```bash
$ git switch -c recovery/lost-work <commit-sha>
$ git show --stat --oneline <commit-sha>
```

The project preserves `origin/original-main` and the `pre-main-switch-2026-09-10` tag. Do not delete either without an explicit backup-retention decision.

## Tags and Releases

Create an annotated release tag only from a clean, reviewed production commit:

```bash
$ git status -sb
$ git tag -a v2.1.0 -m "NOC Intelligence Fusion Center 2.1.0" HEAD
$ git push origin v2.1.0
```

Verify the tag:

```bash
$ git show --no-patch --decorate v2.1.0
$ git ls-remote --tags origin v2.1.0 v2.1.0^{}
```

The GitHub Release and Git tag are separate objects. Pushing a tag alone does not create release notes. Create the GitHub Release through the GitHub web interface or authenticated GitHub CLI.

## Common Issues

### Permission denied or authentication failed

Confirm the remote and authentication method:

```bash
$ git remote -v
$ ssh -T git@github.com
$ git config --get credential.helper
```

For an SSH remote, verify the correct public key is attached to the GitHub account and loaded into the SSH agent. For an HTTPS remote, use a Personal Access Token rather than an account password. Do not repeatedly retry credentials or embed them in URLs.

### Branch is behind or ahead

Fetch first and compare both sides:

```bash
$ git fetch origin
$ git status -sb
$ git log --oneline --left-right HEAD...origin/main
```

If the local branch has no unique commits, use `git pull --ff-only`. If both sides have unique commits, stop and decide whether to merge, rebase a private branch, or create a backup branch before continuing.

### Non-fast-forward push rejected

Another commit exists on the remote that is not in the local branch. Do not force-push. Fetch, inspect the differences, and integrate the remote work:

```bash
$ git fetch origin
$ git log --oneline --left-right HEAD...origin/feature/my-change
$ git pull --rebase origin feature/my-change
```

Use rebase only for a private or explicitly coordinated branch. Shared branches should use the team’s approved merge policy.

### Local changes would be overwritten

Do not discard the changes automatically. Review them, then either commit them to a temporary branch or stash them:

```bash
$ git diff
$ git switch -c wip/save-local-work
$ git add -A
$ git commit -m "WIP: save local work"
```

### Accidentally entered detached HEAD state

A detached HEAD commonly occurs after checking out a tag or commit. If changes were made, preserve them immediately:

```bash
$ git status
$ git switch -c recovery/detached-head-work
```

If no changes were made, switch back to `main` or the intended feature branch.

### A file is not being ignored

Check which rule applies:

```bash
$ git check-ignore -v path/to/file
$ git status --ignored --short
```

If the file is already tracked, `.gitignore` will not affect it. Use `git rm --cached` only after confirming that removing it from version control is intended.

### A secret was committed

Treat the secret as compromised. Revoke or rotate it first, notify the appropriate owner, then remove it from history using an approved repository-history procedure. Do not merely delete the line or add the filename to `.gitignore`; old commits still contain the value.

### Changes were pushed to the wrong branch

Stop before making another push. Record the commit hash, notify collaborators if the branch is shared, and create a backup reference before correcting history:

```bash
$ git branch backup/wrong-branch-push
$ git log --oneline --decorate -10
```

Never delete or rewrite the branch until the intended replacement and recovery path are verified.

## Common Pitfalls

- Running `git pull` without `--ff-only` can create an unplanned merge commit.
- Running `git reset --hard` can permanently remove uncommitted work.
- Using `git push --force` can overwrite another contributor’s commits; use `--force-with-lease` only with explicit approval.
- Working on `main` directly makes review and rollback harder; use a feature or maintenance branch.
- Assuming `.gitignore` removes already tracked files leaves sensitive or generated files in the repository.
- Using `git add .` from the wrong directory can stage unrelated files, local exports, or secrets.
- Rebasing a branch that other people are using changes its commit IDs and complicates everyone’s work.
- Deleting a local branch before pushing or tagging its last useful commit can remove the easiest recovery pointer.
- Checking out a release tag and committing without creating a branch leaves the commit detached.
- Treating a Git tag as a GitHub Release can leave a version without release notes or a published release page.
- Forgetting to fetch before comparing branches can produce decisions based on stale remote references.
- Assuming local `main` is current without checking `git status -sb` can hide that it tracks an older remote commit.

## Git Hygiene Best Practices

- Start each work session with `git fetch origin --prune` and `git status -sb`.
- Keep `main` deployable and use short-lived feature branches for changes.
- Use descriptive branch names such as `feature/keyword-analysis`, `fix/webhook-validation`, or `docs/git-operations`.
- Keep commits focused on one logical change and use clear imperative messages.
- Review `git diff` before staging and `git diff --cached` before committing.
- Run `git diff --check` before every commit to catch whitespace errors.
- Keep generated files, local databases, dependency directories, build output, credentials, and editor files ignored.
- Confirm `.env` and private keys are ignored before creating a commit.
- Push work regularly to a private feature branch so recovery does not depend on one workstation.
- Keep a backup branch or annotated tag before branch migrations, history rewrites, or release preparation.
- Delete merged feature branches only after confirming the merge commit and any required release tag exist remotely.
- Prune stale remote-tracking references with `git fetch origin --prune`; this does not delete active remote branches.
- Avoid unnecessary merge commits and avoid rebasing shared branches.
- Review author identity and commit contents before publishing.
- Keep release tags immutable; create a new corrective release instead of moving a published tag.
- Document unusual branch moves, rollback tags, and migration decisions in the project changelog or operations record.

## Current Repository Verification

```bash
$ git fetch origin --prune
$ git ls-remote --symref origin HEAD
$ git ls-remote --heads origin main original-main architecture/monolith-to-decoupled
$ git ls-remote --tags origin v2.0.0 v2.0.0^{}
```

Expected current state:

- `main` is the GitHub default and production branch.
- `architecture/monolith-to-decoupled` points to the same production baseline as `main`.
- `original-main` preserves the pre-migration branch.
- `v2.0.0` identifies the production release baseline.

## Safe Command Rules

- Prefer `git fetch` before making branch decisions.
- Prefer `git pull --ff-only` for synchronized branches.
- Create a backup branch or tag before risky history operations.
- Stage specific files instead of blindly staging everything.
- Never use `git reset --hard`, `git checkout --`, or force-push shared branches without explicit approval.
- Never commit secrets or rely on `.gitignore` to remove a secret from history.
- Verify branch and commit hashes after every remote branch migration.
