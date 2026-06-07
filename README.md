# AWS CodeCommit IAM Policy

## Overview

This is an IAM policy that controls access to AWS CodeCommit repositories using **Tag-Based Access Control (TBAC)**.

Each IAM user is restricted to operating only on repositories where they are explicitly tagged as an "Owner", "Writer", or "Reader". In addition, direct pushes and merges into protected branches (`main` / `develop`) are denied, enforcing a pull request and review workflow.

---

## Resource Tags Used

| Tag Key | Description | Value Format |
|---|---|---|
| `RepositoryOwner` | Username of the repository owner | IAM username (e.g., `alice`) |
| `RepositoryWrite` | List of users granted write access | A string of usernames separated by delimiters (e.g., `_alice_bob_carol_`) |
| `RepositoryRead` | List of users granted read access | A string of usernames separated by delimiters (e.g., `_alice_dave_`) |

### Delimiters allowed in `RepositoryWrite` / `RepositoryRead`

The following characters can be used as delimiters surrounding the username in `StringLike` conditions such as `*+${aws:username}+*`:

| Delimiter | Character |
|---|---|
| Underscore | `_` |
| Period | `.` |
| Colon | `:` |
| Slash | `/` |
| Equals sign | `=` |
| Plus | `+` |
| Hyphen | `-` |
| At sign | `@` |

Delimiters **do not need to be identical** before and after the username; you may mix different delimiters. However, if a username itself contains one of these characters, false matches may occur. It is therefore recommended to choose a delimiter that never appears in any username.

---

## Policy Statement Details

### 1. `ForceRepositoryOwnerTagOnCreate` — Enforce Owner Tag on Repository Creation

```json
"Action": ["codecommit:CreateRepository", "codecommit:TagResource"]
"Condition": {
  "StringEquals": { "aws:RequestTag/RepositoryOwner": "${aws:username}" },
  "ForAllValues:StringEquals": { "aws:TagKeys": ["RepositoryOwner"] }
}
```

**Purpose:** When a repository is created, this requires the `RepositoryOwner` tag to be set to **the user's own username**, otherwise the creation is not allowed. This guarantees that every repository has an explicit owner.

---

### 2. `AllowAllActionsOnRepository` — Allow All Actions for the Owner

```json
"Action": ["codecommit:*"]
"Condition": {
  "StringEquals": { "aws:ResourceTag/RepositoryOwner": "${aws:username}" }
}
```

**Purpose:** Allows all CodeCommit actions on repositories whose `RepositoryOwner` tag matches the user's username. The owner has full administrative control over the repository.

---

### 3. `AllowRepositoryWriteActionsOnRepository` — Allow Actions for Writers

```json
"Action": [
  "codecommit:List*", "codecommit:Get*", "codecommit:BatchGet*",
  "codecommit:Describe*", "codecommit:GitPull", "codecommit:GitPush",
  "codecommit:CreateBranch", "codecommit:DeleteBranch",
  "codecommit:MergeBranches*", "codecommit:MergePullRequest*",
  "codecommit:BatchDescribeMergeConflicts", "codecommit:CreateUnreferencedMergeCommit",
  "codecommit:CreatePullRequest", "codecommit:PostCommentForPullRequest",
  "codecommit:UpdatePullRequestDescription", "codecommit:UpdatePullRequestStatus",
  "codecommit:UpdatePullRequestTitle",
  "codecommit:DeleteFile", "codecommit:PutFile", "codecommit:CreateCommit"
]
"Condition": {
  "StringLike": { "aws:ResourceTag/RepositoryWrite": "*+${aws:username}+*" }
}
```

**Purpose:** Allows read and write operations on repositories whose `RepositoryWrite` tag includes the user's username. Branch operations, file operations, and basic pull request operations (create, comment, update description/status/title) are granted. Pull request **approval** operations (approval rules, approval state, override) are **not** included; those are available only to the repository owner via Statement 2.

> **Note:** The Deny rule in Statement 4 prohibits direct operations against protected branches.

---

### 4. `DenyDirectPushAndMergeIntoProtectedBranches` — Deny Direct Operations on Protected Branches

```json
"Effect": "Deny"
"Action": [
  "codecommit:GitPush", "codecommit:CreateBranch", "codecommit:DeleteBranch",
  "codecommit:MergeBranches*", "codecommit:MergePullRequest*",
  "codecommit:CreateUnreferencedMergeCommit",
  "codecommit:DeleteFile", "codecommit:PutFile", "codecommit:CreateCommit"
]
"Condition": {
  "StringLikeIfExists": {
    "codecommit:References": ["refs/heads/main", "refs/heads/develop"]
  },
  "StringLike": { "aws:ResourceTag/RepositoryWrite": "*+${aws:username}+*" },
  "Null": { "codecommit:References": "false" }
}
```

**Purpose:** Even for users with `RepositoryWrite` permission, this denies direct pushes and merges into the `main` and `develop` branches. As a result, any changes to protected branches must go through a pull request and review.

> **Key point:** The `Null: { "codecommit:References": "false" }` condition restricts the scope of this Deny rule to operations that carry the `codecommit:References` context key (Git push, branch, merge, and file/commit operations on a branch). Actions that do not support this key—such as pull request approval or metadata updates—are omitted from this statement because they would never match the condition and would have no effect.

---

### 5. `AllowRepositoryReadOnRepository` — Allow Access for Readers

```json
"Action": [
  "codecommit:GitPull", "codecommit:Get*",
  "codecommit:Describe*", "codecommit:BatchGet*", "codecommit:List*"
]
"Condition": {
  "StringLike": { "aws:ResourceTag/RepositoryRead": "*+${aws:username}+*" }
}
```

**Purpose:** Grants read-only access to repositories whose `RepositoryRead` tag includes the user's username. Only browsing and cloning the code are permitted.

---

### 6. `AllowTaggingOnOwnRepo` — Allow the Owner to Manage Access Tags

```json
"Action": ["codecommit:TagResource", "codecommit:UntagResource"]
"Condition": {
  "StringEquals": { "aws:ResourceTag/RepositoryOwner": "${aws:username}" },
  "ForAnyValue:StringEquals": { "aws:TagKeys": ["RepositoryWrite", "RepositoryRead"] }
}
```

**Purpose:** Allows the owner to add or remove the `RepositoryWrite` and `RepositoryRead` tags on their own repositories, enabling them to manage access permissions. Changes to the `RepositoryOwner` tag are not included.

---

### 7. `DenyChangingRepositoryOwnerTag` — Deny Changes to the Owner Tag

```json
"Effect": "Deny"
"Action": ["codecommit:TagResource"]
"Condition": {
  "Null": { "aws:RequestTag/RepositoryOwner": "false" },
  "StringEquals": { "aws:RequestTag/RepositoryOwner": "${aws:username}" }
}
```

**Purpose:** Denies any `TagResource` request that contains a `RepositoryOwner` tag whose value matches the user's own username. This prevents re-tagging or rewriting the `RepositoryOwner` tag after a repository has been created.

---

### 8. `DenyRemovingRepositoryOwnerTag` — Deny Removal of the Owner Tag

```json
"Effect": "Deny"
"Action": ["codecommit:UntagResource"]
"Condition": {
  "ForAnyValue:StringEquals": { "aws:TagKeys": ["RepositoryOwner"] }
}
```

**Purpose:** Prohibits all users from removing the `RepositoryOwner` tag. This prevents the existence of repositories without an owner.

---

### 9. `AllowListRepositoriesGlobally` — Allow Listing Repositories

```json
"Action": ["codecommit:ListRepositories"]
"Resource": "*"
```

**Purpose:** Allows all users to list every repository in the AWS account. Repositories the user has no access to still appear in the name listing, but their contents cannot be viewed or modified.

---

## Permission Matrix

| Action | Owner | Writer | Reader |
|---|:---:|:---:|:---:|
| List repositories | Yes | Yes | Yes |
| Browse / clone code | Yes | Yes | Yes |
| Push to feature branches | Yes | Yes | No |
| Create / update pull requests | Yes | Yes | No |
| Approve pull requests | Yes | No | No |
| Direct push to `main` / `develop` | Yes | No | No |
| Manage `RepositoryWrite` / `RepositoryRead` tags | Yes | No | No |
| Delete repository / change settings | Yes | No | No |

> The owner can also perform direct operations on protected branches, because the Deny in Statement 4 is bound to the `RepositoryWrite` tag condition.

---

## Tag Configuration Example

```
RepositoryOwner  = alice
RepositoryWrite  = _alice_bob_carol_
RepositoryRead   = _alice_bob_carol_dave_eve_
```

In this configuration:
- `alice` is the owner and has full permissions.
- `bob` and `carol` have write permissions (but cannot push directly to protected branches).
- `dave` and `eve` have read-only access.
