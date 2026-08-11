---
name: pr-review-comment
description: Post inline review comments on a GitHub PR given prepared findings. Trigger when user says "submit comments", "post review", "提交评论", "提交下评论", or wants to post review findings on a PR after analysis is done.
allowed-tools: Bash, AskUserQuestion, Read
---

# PR Review Comment Poster

Post batched inline review comments on a GitHub PR via `gh api` REST endpoint.

## Prerequisites

- `gh` CLI installed and authenticated
- PR already reviewed — findings are prepared (file paths, line numbers, comment bodies)

## Input

The skill expects these to be available in conversation context:

1. **PR identifier** — URL like `https://github.com/owner/repo/pull/123` or just PR number (uses current repo)
2. **Findings** — list of comments, each with:
   - `file`: path relative to repo root
   - `line`: end line number in the PR head version of the file
   - `start_line` (optional): start line for multi-line comments
   - `body`: comment text (markdown, may include code suggestions)
3. **Event type** (optional) — `COMMENT` (default), `APPROVE`, or `REQUEST_CHANGES`
4. **Overall message** (optional) — summary body for the review

## Workflow

### Step 1: Resolve PR metadata

```bash
# Extract owner/repo from URL or use current repo
# Get latest commit SHA
gh pr view <NUMBER> --repo <OWNER/REPO> --json commits --jq '.commits[-1].oid'
```

### Step 2: Resolve line numbers

For each finding, verify the line number exists in the PR head version:

```bash
gh api "repos/<OWNER>/<REPO>/contents/<FILE_PATH>?ref=<COMMIT_SHA>" \
  --jq '.content' | base64 -d | grep -n "<pattern>"
```

### Step 3: Show user what will be posted

Use AskUserQuestion to display:
- Each comment: file, line range, body preview
- Event type
- Overall message

Get explicit yes/no approval before posting.

### Step 4: Build and POST JSON payload

Write a JSON file and use `--input`:

```bash
cat <<'PAYLOAD' > /tmp/pr_review.json
{
  "commit_id": "<SHA>",
  "event": "COMMENT",
  "body": "Overall review message.",
  "comments": [
    {
      "path": "src/foo.py",
      "line": 42,
      "body": "Comment text here."
    },
    {
      "path": "src/bar.py",
      "line": 100,
      "start_line": 95,
      "body": "Multi-line comment."
    }
  ]
}
PAYLOAD

gh api repos/<OWNER>/<REPO>/pulls/<NUMBER>/reviews \
  -X POST \
  --input /tmp/pr_review.json \
  --jq '{id, state}'
```

### Step 5: Report result

Show the review ID and confirm it was posted successfully.

## Critical Rules

### DO

- Always batch all comments into ONE review via JSON `--input`
- Always get user approval via AskUserQuestion before posting
- Use `start_line` + `line` for multi-line range comments
- Verify `gh --version` works before starting
- Clean up `/tmp/pr_review.json` after posting

### DO NOT

- Do NOT use `-f 'comments[][path]'` GraphQL-style syntax — it causes field validation errors
- Do NOT include `side`, `start_side`, or `subject_type` fields — they cause 422 Unprocessable Entity errors on the REST endpoint via `gh api`
- Do NOT post without user approval
- Do NOT skip the pending review pattern even for a single comment

## Event Type Guide

| Event | When |
|-------|------|
| `COMMENT` | Neutral feedback, questions, observations (default) |
| `REQUEST_CHANGES` | Blocking bugs, security issues, must-fix items |
| `APPROVE` | Non-blocking suggestions, PR is ready to merge |

## Code Suggestion Format

Include in comment body:

````
Bug: description of the issue.

```suggestion
fixed_code_here()
```
````

## Fork / Cross-repo PRs

For PRs from forks, the commit SHA is still accessible via `gh pr view` on the base repo. Line number resolution uses:

```bash
gh api "repos/<BASE_OWNER>/<BASE_REPO>/contents/<PATH>?ref=<COMMIT_SHA>"
```

This works because GitHub makes fork PR commits available in the base repo's object store.
