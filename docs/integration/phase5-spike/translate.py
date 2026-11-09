#!/usr/bin/env python3
# PROTOTYPE, not production code. Proves the plumbing described in docs/integration/PHASE5_DESIGN.md, section 3.
#
# This is the pre-receive hook of the VIEW repository (the filtered repository a session works in). For each push it:
#   1. refuses refs outside the session's own prefix, and merge commits;
#   2. checks every changed path of every pushed commit (no rename detection, so a rename is a delete plus an add, both checked);
#   3. replays each commit onto the REAL repository (new tree on the real parent, author kept, committer = the gateway);
#   4. pushes the translated tip upstream.
#
# KNOWN LIMITS OF THIS PROTOTYPE (the design fixes them, see PHASE5_DESIGN.md, 4.5):
#   - it re-translates every commit since the view base on every push; the committer date is "now", so a second push to the
#     same branch produces different real commits and upstream refuses it as a non-fast-forward. The design keeps a persistent
#     map (view commit -> real commit) and gives translated commits a committer date derived from the pushed commit, so a
#     retry produces identical commits;
#   - paths are matched with fnmatch (where * crosses "/"), not the dialect in section 4.2;
#   - the allowed and prohibited lists are hard-coded.
import os, subprocess, sys, json, fnmatch
REAL=os.environ['CUSTODY_REAL']; BASE=os.environ['CUSTODY_BASE']; VIEWBASE=os.environ['CUSTODY_VIEWBASE']; UP=os.environ['CUSTODY_UPSTREAM']
ALLOW_WRITE=['server/gateway/*','shared/*']; PROHIBITED=['server/migrations/*','.env*']
hook_env=dict(os.environ)  # the view repo, with the pushed objects in quarantine
view_objects=subprocess.check_output(['git','rev-parse','--git-dir'],env=hook_env,text=True).strip()
quarantine=os.environ.get('GIT_OBJECT_DIRECTORY','')
view_main_objects=os.path.join(os.path.abspath(view_objects),'objects')
def clean_env(extra=None):
    e={k:v for k,v in os.environ.items() if not k.startswith('GIT_') or k in ('GIT_CONFIG_NOSYSTEM','GIT_CONFIG_GLOBAL','GIT_TERMINAL_PROMPT')}
    if extra: e.update(extra)
    return e
ALT=':'.join([p for p in (quarantine, view_main_objects) if p])
def g(args,env=None,inp=None,check=True):
    r=subprocess.run(['git']+args,env=env,input=inp,capture_output=True,text=True)
    if check and r.returncode!=0: raise RuntimeError('git %s: %s'%(' '.join(args),r.stderr.strip()))
    return r.stdout
def view(args,**k): return g(args,env=hook_env,**k)
def real(args,inp=None,extra=None):
    e=clean_env({'GIT_ALTERNATE_OBJECT_DIRECTORIES':ALT,'GIT_DIR':REAL}); 
    if extra: e.update(extra)
    return g(args,env=e,inp=inp)
def refuse(msg): sys.stderr.write('Custody Core refused this push: %s\n'%msg); sys.exit(1)
def allowed(path):
    if any(c.lower()=='.git' for c in path.split('/')) or path.endswith('.gitmodules'): return False
    if any(fnmatch.fnmatch(path.lower(),p.lower()) for p in PROHIBITED): return False   # prohibited: conservative (case-insensitive)
    return any(fnmatch.fnmatch(path,p) for p in ALLOW_WRITE)                             # allowed: exact
for line in sys.stdin.read().splitlines():
    old,new,ref=line.split()
    if not ref.startswith('refs/heads/session/abc/'): refuse('ref not allowed: '+ref)
    if view(['rev-list','--merges',new,'--not',VIEWBASE]).strip(): refuse('merge commits are not accepted')
    commits=view(['rev-list','--reverse','--topo-order',new,'--not',VIEWBASE]).split()
    pv,pr=VIEWBASE,BASE
    for c in commits:
        raw=view(['diff-tree','-r','-z','--no-renames','--raw',pv,c]).split('\0')
        changes=[]; i=0
        while i<len(raw)-1:
            meta=raw[i]; path=raw[i+1]; i+=2
            om,nm,osha,nsha,st=meta[1:].split()
            changes.append((nm,nsha,st[0],path))
        for nm,nsha,st,path in changes:
            if nm in ('120000','160000'): refuse('symlinks and submodules are not accepted: '+path)
            if not allowed(path): refuse('path not allowed: '+path+' (%s)'%st)
        # replay onto the real parent's tree using a temporary index
        idx=os.path.join(os.environ['CUSTODY_TMP'],'idx.%d'%os.getpid())
        if os.path.exists(idx): os.remove(idx)
        real(['read-tree',pr],extra={'GIT_INDEX_FILE':idx})
        for nm,nsha,st,path in changes:
            if st=='D': real(['update-index','--force-remove','--',path],extra={'GIT_INDEX_FILE':idx})
            else: real(['update-index','--add','--cacheinfo','%s,%s,%s'%(nm,nsha,path)],extra={'GIT_INDEX_FILE':idx})
        tree=real(['write-tree'],extra={'GIT_INDEX_FILE':idx}).strip()
        msg=view(['log','-1','--format=%B',c]).rstrip('\n'); an=view(['log','-1','--format=%an',c]).strip(); ae=view(['log','-1','--format=%ae',c]).strip(); ad=view(['log','-1','--format=%aI',c]).strip()
        newreal=real(['commit-tree',tree,'-p',pr],inp=msg+'\n\nCustody-Work-Session: abc\n',extra={'GIT_AUTHOR_NAME':an,'GIT_AUTHOR_EMAIL':ae,'GIT_AUTHOR_DATE':ad,'GIT_COMMITTER_NAME':'Custody','GIT_COMMITTER_EMAIL':'gateway@custody.invalid'}).strip()
        open(os.environ['CUSTODY_MAP'],'a').write('%s %s\n'%(c,newreal))
        sys.stderr.write('   view %s -> real %s  (%d path(s) checked)\n'%(c[:8],newreal[:8],len(changes)))
        pv,pr=c,newreal
    r=real(['push','-q',UP,'%s:%s'%(pr,ref)])
