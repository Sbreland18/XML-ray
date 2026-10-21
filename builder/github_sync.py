"""Keep the Release Manager's project folder in step with GitHub, without needing Git.

(Ported from GAMbit's builder.)

pull():  downloads the branch from GitHub and updates the project folder. Files you changed
         here since the last pull are copied to _sync_backup/<time>/ before anything is
         overwritten, and files that only exist here are left alone.
push():  uploads the files you changed here as one commit (GitHub's Git Data API), but only
         when nobody else has pushed since your last pull – otherwise it asks you to pull.

The state of the last pull/push (commit + a hash of every file) is kept in
.builder_sync.json in the project folder, so the Builder knows what *you* changed.
If the folder is a Git clone, the Release Manager can use Git instead.
"""

from __future__ import annotations

import base64
import datetime
import fnmatch
import hashlib
import io
import json
import os
import shutil
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

MANIFEST = ".builder_sync.json"
BACKUP_DIR = "_sync_backup"
ALWAYS_SKIP = [".git/", ".venv/", "venv/", "dist/", "build/", "__pycache__/", "*.pyc",
               BACKUP_DIR + "/", MANIFEST, ".pytest_cache/", "*.tmp", ".idea/", ".vscode/",
               "Thumbs.db", ".DS_Store"]


# ================================================================== files ===
def _patterns(root: str) -> list[str]:
    pats = list(ALWAYS_SKIP)
    try:
        with open(os.path.join(root, ".gitignore"), encoding="utf-8") as fh:
            pats += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    except OSError:
        pass
    return pats


def ignored(rel: str, pats: list[str]) -> bool:
    rel = rel.replace("\\", "/")
    parts = rel.split("/")
    for p in pats:
        p = p.lstrip("/")
        if p.endswith("/"):
            d = p.rstrip("/")
            if any(fnmatch.fnmatch(x, d) for x in parts[:-1]) or rel.startswith(d + "/"):
                return True
        elif fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(parts[-1], p):
            return True
    return False


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def local_files(root: str) -> dict[str, str]:
    """{relative path: sha256} for every project file that would be on GitHub."""
    pats = _patterns(root)
    out = {}
    for dirpath, dirs, files in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        dirs[:] = [d for d in dirs if not ignored(rel_dir + d + "/", pats)]
        for f in files:
            rel = rel_dir + f
            if ignored(rel, pats):
                continue
            with open(os.path.join(dirpath, f), "rb") as fh:
                out[rel] = _sha(fh.read())
    return out


def load_manifest(root: str) -> dict:
    try:
        with open(os.path.join(root, MANIFEST), encoding="utf-8") as fh:
            m = json.load(fh)
        return m if isinstance(m, dict) else {}
    except (OSError, ValueError):
        return {}


def save_manifest(root: str, commit: str, files: dict[str, str], branch: str):
    tmp = os.path.join(root, MANIFEST + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"commit": commit, "branch": branch, "files": files,
                   "when": datetime.datetime.now().isoformat(timespec="seconds")}, fh,
                  indent=1, sort_keys=True)
    os.replace(tmp, os.path.join(root, MANIFEST))


# ================================================================== plans ===
def pull_plan(local: dict[str, str], base: dict[str, str], remote: dict[str, str],
              pats: list[str] | None = None) -> dict[str, list[str]]:
    """A three-way comparison like git's. base = file hashes at the last sync (empty before
    the first one).
    → write       changed on GitHub only – take GitHub's copy
      keep_local  changed here only – keep yours (it goes up with the next push)
      conflict    changed in both places (or different before the first sync)
      delete      deleted on GitHub, unchanged here
      unchanged"""
    pats = pats or []
    plan = {"write": [], "delete": [], "keep_local": [], "conflict": [], "unchanged": []}
    for path, rsha in remote.items():
        if ignored(path, pats):
            continue
        lsha, bsha = local.get(path), base.get(path)
        if lsha == rsha:
            plan["unchanged"].append(path)
        elif lsha is None:
            if bsha is None:
                plan["write"].append(path)          # new on GitHub
            else:
                plan["keep_local"].append(path)     # you deleted it here – keep it deleted
        elif lsha == bsha:
            plan["write"].append(path)              # only GitHub changed it
        elif rsha == bsha:
            plan["keep_local"].append(path)         # only you changed it
        else:
            plan["conflict"].append(path)
    for path in base:
        if path in remote or path not in local or ignored(path, pats):
            continue
        if local[path] == base[path]:
            plan["delete"].append(path)
        else:
            plan["keep_local"].append(path)
    for k in plan:
        plan[k].sort()
    return plan


class Conflict(RuntimeError):
    def __init__(self, files: list[str]):
        super().__init__(f"{len(files)} file(s) changed both here and on GitHub: " +
                         ", ".join(files[:12]) + (" …" if len(files) > 12 else ""))
        self.files = files


def push_plan(local: dict[str, str], base: dict[str, str]) -> dict[str, list[str]]:
    """Files changed here since the last sync → {add, change, delete}."""
    return {"add": sorted(p for p in local if p not in base),
            "change": sorted(p for p in local if p in base and local[p] != base[p]),
            "delete": sorted(p for p in base if p not in local)}


# ================================================================= GitHub ===
class EmptyRepo(RuntimeError):
    """The repository has no commits yet (GitHub answers 409 "Git Repository is empty")."""


class Api:
    def __init__(self, repo: str, token: str = "", log=print, opener=None):
        self.repo, self.token, self.log = repo, (token or "").strip(), log
        self.ctx = ssl.create_default_context()
        self.opener = opener        # tests can pass a fake urlopen

    def _req(self, method: str, url: str, data=None, raw: bool = False):
        if isinstance(data, (dict, list)):
            data = json.dumps(data).encode()
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "XML-ray-Release-Manager",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            open_ = self.opener or (lambda r: urllib.request.urlopen(r, context=self.ctx,
                                                                     timeout=300))
            with open_(req) as r:
                body = r.read()
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:400]
            if e.code == 409 and "empty" in detail.lower():
                raise EmptyRepo(f"{self.repo} is empty") from None
            if e.code == 404:
                raise RuntimeError(f"GitHub can't find {self.repo} (or the token can't see it)."
                                   f" {detail}") from None
            if e.code in (401, 403):
                raise RuntimeError("GitHub refused the token – check it has Contents: Read "
                                   f"and write for {self.repo}. {detail}") from None
            raise RuntimeError(f"GitHub {method} failed ({e.code}): {detail}") from None
        if raw:
            return body
        return json.loads(body) if body else {}

    def api(self, method: str, path: str, data=None):
        return self._req(method, f"https://api.github.com/repos/{self.repo}{path}", data)

    def head(self, branch: str) -> str:
        """The branch's latest commit, or '' when the repository has no commits yet."""
        try:
            return self.api("GET", f"/commits/{urllib.parse.quote(branch)}")["sha"]
        except EmptyRepo:
            return ""

    def put_contents(self, rel: str, data: bytes, message: str, branch: str) -> str:
        """Create one file with the Contents API – the only way to make the first commit
        in an empty repository. Returns the new commit sha."""
        res = self.api("PUT", f"/contents/{urllib.parse.quote(rel)}",
                       {"message": message, "branch": branch,
                        "content": base64.b64encode(data).decode()})
        return (res.get("commit") or {}).get("sha", "")

    def zipball(self, sha: str) -> bytes:
        return self._req("GET", f"https://api.github.com/repos/{self.repo}/zipball/{sha}",
                         raw=True)


def remote_files(zip_bytes: bytes) -> dict[str, bytes]:
    """GitHub's zip has one top folder (owner-repo-sha/); strip it."""
    out = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            name = info.filename.split("/", 1)[1] if "/" in info.filename else ""
            if not name or name.startswith("/") or ".." in name.split("/"):
                continue
            out[name] = z.read(info)
    return out


# =================================================================== pull ===
def pull(root: str, api: Api, branch: str, log=print, dry: bool = False,
         conflicts: str = "stop") -> dict:
    """Bring the project folder up to date with GitHub. conflicts: 'stop' (raise Conflict),
    'theirs' (back up yours, take GitHub's) or 'mine' (keep yours; it's uploaded with the
    next push)."""
    sha = api.head(branch)
    man = load_manifest(root)
    if not sha:
        log(f"{api.repo} is empty – nothing to download. Your files will be uploaded as the "
            "first version when you publish.")
        save_manifest(root, "", {}, branch)
        return {"write": [], "delete": [], "keep_local": [], "conflict": [], "unchanged": [],
                "applied": [], "empty": True}
    log(f"GitHub {api.repo}@{branch} is at {sha[:7]}"
        + (f" (last sync here: {man['commit'][:7]})" if man.get("commit") else
           " (first sync for this folder)"))
    files = remote_files(api.zipball(sha))
    remote = {p: _sha(b) for p, b in files.items()}
    pats = _patterns(root)
    local = local_files(root)
    plan = pull_plan(local, man.get("files", {}), remote, pats)
    log(f"{len(plan['write'])} file(s) to update from GitHub, {len(plan['delete'])} to remove, "
        f"{len(plan['keep_local'])} changed only here (kept), {len(plan['conflict'])} changed "
        f"in both places, {len(plan['unchanged'])} already the same.")
    if dry:
        return plan
    if plan["conflict"] and conflicts == "stop":
        raise Conflict(plan["conflict"])
    take = plan["write"] + (plan["conflict"] if conflicts == "theirs" else [])
    backup = [p for p in take if p in local]
    if backup:
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        bdir = os.path.join(root, BACKUP_DIR, stamp)
        for rel in backup:
            dst = os.path.join(bdir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(os.path.join(root, rel), dst)
        log(f"Copied this folder's version of {len(backup)} file(s) to {BACKUP_DIR}/{stamp} "
            "before updating them.")
    for rel in take:
        dst = os.path.join(root, rel)
        os.makedirs(os.path.dirname(dst) or root, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dst) or root, prefix=".sync-")
        with os.fdopen(fd, "wb") as fh:
            fh.write(files[rel])
        os.replace(tmp, dst)
    for rel in plan["delete"]:
        try:
            os.remove(os.path.join(root, rel))
        except OSError:
            pass
    plan["applied"] = take
    # new baseline = GitHub's version of every file it has; your own changes stay "changed"
    base = {p: h for p, h in remote.items() if not ignored(p, pats)}
    save_manifest(root, sha, base, branch)
    return plan


# =================================================================== push ===
def push(root: str, api: Api, branch: str, message: str, log=print,
         exclude: tuple = ()) -> str:
    """Upload this folder's changes as one commit. Returns the new commit sha ('' if there
    was nothing to upload). `exclude` files are left for later (latest.json goes last)."""
    man = load_manifest(root)
    head = api.head(branch)
    if not head:
        # empty repository: the Git Data API needs one commit first, so create it with
        # the Contents API (.gitignore, or a README), then upload everything else
        first = ".gitignore" if os.path.isfile(os.path.join(root, ".gitignore")) else \
            "README.md"
        path = os.path.join(root, first)
        data = open(path, "rb").read() if os.path.isfile(path) else b"# XML-ray\n"
        log(f"{api.repo} is empty – creating its first commit ({first}) …")
        head = api.put_contents(first, data, message, branch)
        if not head:
            raise RuntimeError("GitHub didn't create the first commit.")
        man = {"commit": head, "files": {first: _sha(data)}}
        save_manifest(root, head, man["files"], branch)
    if not man.get("commit"):
        raise RuntimeError("Get the latest files from GitHub first, so the Release Manager knows "
                           "which changes are yours.")
    if head != man["commit"]:
        raise RuntimeError(f"Someone pushed to {branch} since your last pull ({head[:7]} vs "
                           f"{man['commit'][:7]}). Click \u201cGet latest from GitHub\u201d, then "
                           "publish again.")
    base = man.get("files", {})
    local = {p: h for p, h in local_files(root).items() if p not in exclude}
    local.update({p: base[p] for p in exclude if p in base})   # unchanged for now
    plan = push_plan(local, base)
    n = sum(len(v) for v in plan.values())
    if not n:
        log("No source changes to upload.")
        return ""
    log(f"Uploading {len(plan['add'])} new, {len(plan['change'])} changed and "
        f"{len(plan['delete'])} removed file(s) …")
    base_tree = api.api("GET", f"/git/commits/{head}")["tree"]["sha"]
    tree = []
    for rel in plan["add"] + plan["change"]:
        with open(os.path.join(root, rel), "rb") as fh:
            blob = api.api("POST", "/git/blobs", {"content": base64.b64encode(fh.read())
                                                  .decode(), "encoding": "base64"})
        tree.append({"path": rel, "mode": "100644", "type": "blob", "sha": blob["sha"]})
    for rel in plan["delete"]:
        tree.append({"path": rel, "mode": "100644", "type": "blob", "sha": None})
    new_tree = api.api("POST", "/git/trees", {"base_tree": base_tree, "tree": tree})["sha"]
    commit = api.api("POST", "/git/commits", {"message": message, "tree": new_tree,
                                              "parents": [head]})["sha"]
    api.api("PATCH", f"/git/refs/heads/{branch}", {"sha": commit, "force": False})
    save_manifest(root, commit, local, branch)
    log(f"Pushed {n} file(s) as commit {commit[:7]}.")
    return commit


def note_remote_file(root: str, rel: str, data: bytes, commit: str):
    """After the Builder itself updates one file on GitHub (latest.json), move the baseline
    forward so the next push/pull doesn't see a false conflict."""
    man = load_manifest(root)
    files = dict(man.get("files", {}))
    files[rel] = _sha(data)
    save_manifest(root, commit or man.get("commit", ""), files, man.get("branch", "main"))
