#!/usr/bin/env bash
# PROTOTYPE for docs/integration/PHASE5_DESIGN.md (section 3). Plain git and Python 3 only; works in a temporary directory
# and touches nothing else. Run:  bash docs/integration/phase5-spike/run.sh
#
# It shows, with real git:
#   1. a filtered "view" of a repository (allowed paths minus prohibited paths, ONE synthetic commit, fixed identity and dates)
#      is deterministic and contains none of the excluded content, including blobs that exist only in old history;
#   2. work done in the view can be replayed onto the real history by the gateway (author kept, committer = gateway);
#   3. hostile pushes are refused and nothing reaches the upstream repository.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT; cd "$W"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0
ALICE='-c user.name=Alice -c user.email=alice@example.com'; MAL='-c user.name=Mallory -c user.email=mallory@example.com'
say() { printf '\n== %s\n' "$*"; }
pass=0; fail=0; check() { if [ "$2" = ok ]; then pass=$((pass+1)); printf '  PASS  %s\n' "$1"; else fail=$((fail+1)); printf '  FAIL  %s\n' "$1"; fi; }

say "1. A real repository: history includes a .env that was later removed, plus a prohibited migrations area"
git init -q --bare upstream.git && git clone -q upstream.git work 2>/dev/null
( cd work && git checkout -q -b main && mkdir -p server/gateway server/migrations shared docs \
  && echo "SECRET=old-value" > .env && echo v1 > server/app.ts && echo g1 > server/gateway/router.ts && echo m1 > server/migrations/001.sql \
  && echo s1 > shared/util.ts && echo d1 > docs/readme.md && git add -A && git $ALICE commit -q -m first \
  && git rm -q -f .env && git $ALICE commit -q -m "remove env (the old value stays in history)" \
  && echo v2 > server/app.ts && git $ALICE commit -q -am second && git push -q origin main )
BASE=$(git --git-dir=upstream.git rev-parse main)
git clone -q --bare upstream.git real     # the gateway's full mirror: never exposed to a session
OLDENV=$(git --git-dir=real rev-parse "$BASE~2:.env"); MIG=$(git --git-dir=real rev-parse "$BASE:server/migrations/001.sql")

say "2. Build the view: read server/** and shared/**, minus server/migrations/** and .env*, as one deterministic synthetic commit"
build_view() {
  rm -rf "$1"; git init -q --bare "$1"; export GIT_INDEX_FILE="$W/idx.tmp"; rm -f "$GIT_INDEX_FILE"
  git --git-dir=real ls-tree -r -z "$BASE" | tr '\0' '\n' | while IFS=$'\t' read -r meta path; do
    set -- $meta; mode=$1; type=$2; sha=$3
    [ "$type" = blob ] && { [ "$mode" = 100644 ] || [ "$mode" = 100755 ]; } || continue   # never symlinks or submodules
    case "$path" in server/migrations/*|.env*) continue;; server/*|shared/*) printf '%s %s\t%s\n' "$mode" "$sha" "$path";; esac
  done | git --git-dir=real update-index --index-info
  local tree; tree=$(git --git-dir=real write-tree)
  local v; v=$(GIT_AUTHOR_NAME=Custody GIT_AUTHOR_EMAIL=gateway@custody.invalid GIT_AUTHOR_DATE=2000-01-01T00:00:00Z \
     GIT_COMMITTER_NAME=Custody GIT_COMMITTER_EMAIL=gateway@custody.invalid GIT_COMMITTER_DATE=2000-01-01T00:00:00Z \
     git --git-dir=real commit-tree -m "Session base" "$tree")
  unset GIT_INDEX_FILE
  echo "$v" | git --git-dir=real pack-objects -q --revs --stdout | git --git-dir="$1" unpack-objects -q   # only what the view needs
  git --git-dir="$1" update-ref refs/heads/main "$v"; git --git-dir="$1" symbolic-ref HEAD refs/heads/main; echo "$v"
}
V1=$(build_view view.git); V2=$(build_view view2.git)
[ "$V1" = "$V2" ] && check "rebuilding the view gives the identical commit (deterministic)" ok || check "rebuilding the view gives the identical commit" no
git --git-dir=view.git cat-file -e "$OLDENV" 2>/dev/null && check "historical .env blob absent from the view" no || check "historical .env blob absent from the view" ok
git --git-dir=view.git cat-file -e "$MIG" 2>/dev/null && check "prohibited migration blob absent from the view" no || check "prohibited migration blob absent from the view" ok
[ "$(git --git-dir=view.git rev-list --count main)" = 1 ] && check "the view has no history (one commit)" ok || check "the view has no history" no
[ "$(git --git-dir=view.git ls-tree -r --name-only main | sort | tr '\n' ' ')" = "server/app.ts server/gateway/router.ts shared/util.ts " ] && check "the view holds exactly the allowed files" ok || check "the view holds exactly the allowed files" no

say "3. The executor works in a clone of the view; the gateway's hook translates the push onto the real history"
cp "$HERE/translate.py" view.git/hooks/pre-receive && chmod +x view.git/hooks/pre-receive; mkdir -p tmp; : > map.txt
export CUSTODY_REAL=$W/real CUSTODY_BASE=$BASE CUSTODY_VIEWBASE=$V1 CUSTODY_TMP=$W/tmp CUSTODY_MAP=$W/map.txt CUSTODY_UPSTREAM=$W/upstream.git
git clone -q view.git exec 2>/dev/null
( cd exec && git checkout -q -b session/abc/work && echo "g2 by alice" >> server/gateway/router.ts && git $ALICE commit -q -am "change in the allowed area" \
  && mkdir -p shared && echo new > shared/newfile.ts && chmod +x shared/newfile.ts && git $ALICE add -A && git $ALICE commit -q -m "new executable file in the allowed area" )
( cd exec && git push origin session/abc/work >/dev/null 2>&1 ) && check "a clean push is accepted" ok || check "a clean push is accepted" no
[ "$(git --git-dir=upstream.git diff --name-status "$BASE" session/abc/work 2>/dev/null | tr '\t\n' '  ')" = "M server/gateway/router.ts A shared/newfile.ts " ] && check "upstream gained exactly the two allowed changes" ok || check "upstream gained exactly the two allowed changes" no
git --git-dir=upstream.git merge-base --is-ancestor "$BASE" session/abc/work 2>/dev/null && check "translated commits sit on the real base (real history kept)" ok || check "translated commits sit on the real base" no
[ "$(git --git-dir=upstream.git log -1 --format='%an|%cn' session/abc/work 2>/dev/null)" = "Alice|Custody" ] && check "author kept, committer is the gateway" ok || check "author kept, committer is the gateway" no
[ "$(git --git-dir=upstream.git ls-tree session/abc/work shared/newfile.ts 2>/dev/null | cut -d' ' -f1)" = 100755 ] && check "file mode preserved" ok || check "file mode preserved" no
git --git-dir=upstream.git diff --quiet "$BASE" session/abc/work -- server/migrations .env 2>/dev/null && check "prohibited paths untouched in upstream" ok || check "prohibited paths untouched in upstream" no
TIP=$(git --git-dir=upstream.git rev-parse session/abc/work)

say "4. Hostile pushes (each from the clean branch): all must be refused, nothing may reach upstream"
VTIP=$(git --git-dir=view.git rev-parse session/abc/work)
cd exec
hostile() {  # name, shell snippet, expected phrase in the refusal
  git checkout -q session/abc/work && git reset -q --hard origin/session/abc/work 2>/dev/null || git reset -q --hard "$VTIP"
  eval "$2" >/dev/null 2>&1; git $MAL add -A; git $MAL commit -q -m "$1" 2>/dev/null || { check "$1 (could not stage: not a test)" no; return; }
  out=$(git push origin session/abc/work 2>&1); code=$?
  if [ $code -ne 0 ] && echo "$out" | grep -q "$3"; then check "refused: $1" ok; else check "refused: $1" no; fi
}
hostile "add a prohibited name (.env)"             "echo SECRET=x > .env"                                       "path not allowed: .env"
hostile "write outside the allowed area"           "echo x > server/app.ts.bak"                                 "path not allowed"
hostile "modify a read-only file"                  "echo more >> server/app.ts"                                 "path not allowed: server/app.ts"
hostile "delete a read-only file"                  "git rm -q server/app.ts"                                    "path not allowed: server/app.ts"
hostile "add a file under migrations"              "mkdir -p server/migrations && echo x > server/migrations/002.sql" "path not allowed"
hostile "case trick on a prohibited path"          "mkdir -p server/MIGRATIONS && echo x > server/MIGRATIONS/003.sql" "path not allowed"
hostile "add a symlink in the allowed area"        "ln -sf /etc/passwd shared/link"                             "symlinks and submodules"
hostile "add .gitmodules"                          "printf '[submodule \"x\"]\n' > shared/.gitmodules"          "path not allowed"
hostile "move a read-only file into the area"      "git mv server/app.ts shared/app.ts"                         "path not allowed: server/app.ts"
git checkout -q session/abc/work && git reset -q --hard origin/session/abc/work
git checkout -q -b side HEAD~1 && echo s > shared/side.ts && git $MAL add -A && git $MAL commit -q -m side && git checkout -q session/abc/work && git $MAL merge -q --no-ff side -m merge >/dev/null 2>&1
out=$(git push origin session/abc/work 2>&1); echo "$out" | grep -q "merge commits are not accepted" && check "refused: merge commit" ok || check "refused: merge commit" no
git checkout -q session/abc/work && git reset -q --hard origin/session/abc/work && echo ok >> shared/newfile.ts && git $MAL commit -q -am ok
out=$(git push origin HEAD:refs/heads/main 2>&1); echo "$out" | grep -q "ref not allowed" && check "refused: push to main" ok || check "refused: push to main" no
out=$(git push origin HEAD:refs/heads/session/other/work 2>&1); echo "$out" | grep -q "ref not allowed" && check "refused: another session's branch" ok || check "refused: another session's branch" no
cd ..
[ "$(git --git-dir=upstream.git rev-parse session/abc/work)" = "$TIP" ] && [ "$(git --git-dir=upstream.git rev-parse main)" = "$BASE" ] && check "upstream unchanged by every hostile push" ok || check "upstream unchanged by every hostile push" no

printf '\n%d passed, %d failed\n' "$pass" "$fail"; [ "$fail" -eq 0 ]
