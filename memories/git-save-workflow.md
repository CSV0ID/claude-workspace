---
name: git-save-workflow
description: How the user wants chat/data saved and committed/pushed per save
metadata: 
  node_type: memory
  type: feedback
  originSessionId: cedb0f6a-07d0-45fe-85d2-c43288409f43
---

The user wants every chat and project artifact saved to files under the `nmap/` folder, and after each save, committed and **pushed to origin on a new branch named t1, t2, t3, ...** (incrementing per save).

**Why:** they want a versioned trail of the work, each save isolated on its own branch.

**How to apply:** after writing/updating files, `git add` them, commit with a descriptive message, create the next `tN` branch, and push it to origin. Track which `tN` was last used (so far: t6). Repo: CSV0ID/claude-workspace (origin on GitHub; full URL `https://github.com/CSV0ID/claude-workspace.git` — checked-out remote may carry a `your-repo` placeholder that 404s, reset origin if push fails). Relates to [[ai-pentest-assistant-project]].
