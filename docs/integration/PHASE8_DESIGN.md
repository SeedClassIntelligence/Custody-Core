# Phase 8 design note: evidence-gated promotion

Gate CL-14 (`tests/promotion.test.ts`). Migration `018`.

## What it is

Promotion moves a repository's **default branch forward** to a commit a session produced. Until now a session's work only ever lived on `session/<id>/...` branches; promotion is the one step that touches the default branch, and it is gated twice: by evidence, and by the owner.

```
asked for (principal with repositories:promote, or the owner)  -> pending   refused unless the evidence is ready for that commit
approved by the OWNER only                                     -> approved  evidence checked again
carried out by the gateway with the repository host's credentials -> completed | failed
pending -> rejected (owner)
```

## Decisions made while designing, for review

1. **Approval is human, always.** There is no machine route that approves or rejects, and the database refuses an approval by anyone but the session's sponsor (`creator:<id>`). The spec allowed approval "through an active approval policy"; no such policy exists, so none is built. A principal can only *ask* (scope `repositories:promote`, a high-consequence scope that cannot be held with work scopes).
2. **Evidence is checked three times**: when asked (refused, nothing recorded, with the evaluation in the answer), at approval (a revoked key or inactive issuer blocks it), and again just before the push (it fails the request). The evaluation is stored with the request and again at completion.
3. **Fast-forward only, fail closed.** If the default branch has moved on since the session's base, the promotion **fails** (`default_branch_moved`) and nothing changes. There is no merging in this platform; the work is not lost (it is on its session branch in the owner's repository) and a new session can start from the current code. The Phase 5 design deferred this question to here.
4. **Only the gateway's own commits can land.** Every commit between the default branch and the promoted commit must be one the gateway recorded for this session, so every line has an attribution. The push uses a lease on the default branch's current tip.
5. **A promoted commit may be any of the session's commits** (default: the newest), not only the last. The evidence must be for that exact commit.
6. **Promotion ends the session**: it becomes `completed`, its credential is revoked and the gateway's copy deleted. The requester can still close it. The scheduler closes (not expires) a completed session when its end time passes; this also fixes a latent error, since the database does not allow `completed` to become `expired`.
7. **Uniqueness**: one live request per session, branch and commit. The spec's plain unique constraint would have blocked asking again after a transient failure; a rejected or failed request can be asked for again.
8. **Failure is recorded, not hidden**: `promotion.failed` with a code and a short message (never credentials); a request left `approved` by a crash is resumed by approving it again (idempotent: if the branch is already at the commit it completes without pushing).
9. **Statuses**: `pending, approved, completed, rejected, failed` (`failed` is an addition to the spec's list).

## Not guaranteed, stated plainly

- If the repository host has protections of its own on the default branch (required reviews, required status checks), the host may refuse the push; the request then fails with `push_refused`. The Custody Core lock only forbids deleting or force-pushing the default branch.
- Passing evidence says the named issuer vouched for that commit, not that the commit is correct.
