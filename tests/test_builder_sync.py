"""Release Manager: sync source code with GitHub without Git (fake GitHub, no network)."""

import base64
import hashlib
import io
import json
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "builder"))
import github_sync as gs  # noqa: E402


class FakeGitHub:
    """Just enough of the GitHub REST API, in memory."""

    def __init__(self, files: dict[str, bytes]):
        self.commits = {}        # sha -> {files, parent}
        self.head = self._commit(dict(files), None) if files else ""
        self.blobs, self.trees = {}, {}

    def _commit(self, files, parent):
        sha = hashlib.sha1(json.dumps({k: v.decode() for k, v in sorted(files.items())},
                                      sort_keys=True).encode() + str(parent).encode()).hexdigest()
        self.commits[sha] = {"files": files, "parent": parent}
        return sha

    def edit(self, path, data):       # someone else pushes
        files = dict(self.commits[self.head]["files"])
        if data is None:
            files.pop(path, None)
        else:
            files[path] = data
        self.head = self._commit(files, self.head)

    def opener(self, req):
        url, method = req.full_url, req.get_method()
        body = json.loads(req.data) if req.data else None
        path = url.split("/repos/o/r", 1)[1]
        if not self.head and not (method == "PUT" and path.startswith("/contents/")):
            import urllib.error
            raise urllib.error.HTTPError(url, 409, "Conflict", {}, io.BytesIO(
                b'{"message":"Git Repository is empty.","status":"409"}'))
        if method == "PUT" and path.startswith("/contents/"):
            files = dict(self.commits[self.head]["files"]) if self.head else {}
            files[path.split("/contents/", 1)[1]] = base64.b64decode(body["content"])
            self.head = self._commit(files, self.head or None)
            return _Resp(json.dumps({"commit": {"sha": self.head}}).encode())
        if method == "GET" and path.startswith("/commits/"):
            out = {"sha": self.head}
        elif method == "GET" and path.startswith("/zipball/"):
            sha = path.split("/")[-1]
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                for p, d in self.commits[sha]["files"].items():
                    z.writestr(f"o-r-{sha[:7]}/{p}", d)
            return _Resp(buf.getvalue())
        elif method == "GET" and path.startswith("/git/commits/"):
            out = {"tree": {"sha": "tree-" + path.split("/")[-1]}}
        elif method == "POST" and path == "/git/blobs":
            data = base64.b64decode(body["content"])
            sha = hashlib.sha1(data).hexdigest()
            self.blobs[sha] = data
            out = {"sha": sha}
        elif method == "POST" and path == "/git/trees":
            base = self.commits[body["base_tree"][5:]]["files"]
            files = dict(base)
            for e in body["tree"]:
                if e["sha"] is None:
                    files.pop(e["path"], None)
                else:
                    files[e["path"]] = self.blobs[e["sha"]]
            sha = "t" + hashlib.sha1(os.urandom(8)).hexdigest()
            self.trees[sha] = files
            out = {"sha": sha}
        elif method == "POST" and path == "/git/commits":
            assert body["parents"] == [self.head]
            out = {"sha": self._commit(self.trees[body["tree"]], self.head)}
            self._pending = out["sha"]
        elif method == "PATCH" and path.startswith("/git/refs/heads/"):
            self.head = body["sha"]
            out = {}
        else:
            raise AssertionError(f"unexpected {method} {path}")
        return _Resp(json.dumps(out).encode())

    def files(self):
        return self.commits[self.head]["files"]


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _api(fake):
    return gs.Api("o/r", "tok", lambda *_a: None, opener=fake.opener)


def _write(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)


def _read(root, rel):
    with open(os.path.join(root, rel), encoding="utf-8") as fh:
        return fh.read()



def _pipeline(root, monkeypatch, fake, version="1.0.1"):
    import release_manager as rm
    monkeypatch.setattr(rm, "ROOT", root)
    monkeypatch.setattr(rm.github_sync, "Api",
                        lambda repo, token, log=print: _RealApi("o/r", "tok", log, opener=fake.opener))
    p = rm.Pipeline(dict(owner="o", repo="r", token="tok", version=version))
    p.branch = "main"
    return p


_RealApi = gs.Api


def test_three_way_pull_and_conflicts(tmp_path):
    fake = FakeGitHub({"a.py": b"A1", "b.py": b"B1", "c.py": b"C1"})
    root = str(tmp_path)
    gs.pull(root, _api(fake), "main", log=lambda *_a: None)
    _write(root, "b.py", "B-mine")
    _write(root, "c.py", "C-mine")
    _write(root, "dist/XML-ray-Setup-1.0.0.exe", "x")
    fake.edit("a.py", b"A2")
    fake.edit("c.py", b"C2")
    with pytest.raises(gs.Conflict) as e:
        gs.pull(root, _api(fake), "main", log=lambda *_a: None)
    assert e.value.files == ["c.py"]
    gs.pull(root, _api(fake), "main", log=lambda *_a: None, conflicts="theirs")
    assert _read(root, "a.py") == "A2" and _read(root, "b.py") == "B-mine"
    assert _read(root, "c.py") == "C2"
    assert os.listdir(os.path.join(root, gs.BACKUP_DIR))


def test_empty_repo_first_publish_without_git(tmp_path, monkeypatch):
    """The situation without Git: GitHub is empty and the folder has never synced."""
    fake = FakeGitHub({})
    _write(str(tmp_path), ".gitignore", "dist/\n.venv/\n")
    _write(str(tmp_path), "run.py", "print(1)")
    _write(str(tmp_path), "xmlray/__version__.py", '__version__ = "1.0.1"')
    _write(str(tmp_path), "dist/installer/XML-ray-Setup-1.0.1.exe", "binary")
    _write(str(tmp_path), ".venv/lib/x.py", "junk")
    sha = _pipeline(tmp_path, monkeypatch, fake)._push_source()
    assert sha == fake.head
    assert sorted(fake.files()) == [".gitignore", "run.py", "xmlray/__version__.py"]


def test_files_uploaded_by_hand_then_publish(tmp_path, monkeypatch):
    """Files were uploaded on github.com, the folder has never synced, and the version
    number changed locally: compare first, then upload only the change."""
    fake = FakeGitHub({"run.py": b"print(1)", "xmlray/__version__.py": b'__version__ = "1.0.0"'})
    _write(str(tmp_path), "run.py", "print(1)")
    _write(str(tmp_path), "xmlray/__version__.py", '__version__ = "1.0.0"')
    p = _pipeline(tmp_path, monkeypatch, fake)
    p._pull()                                     # first sync: everything identical
    _write(str(tmp_path), "xmlray/__version__.py", '__version__ = "1.0.1"')
    before = fake.head
    sha = p._push_source()
    assert sha and sha != before
    assert fake.files()["xmlray/__version__.py"] == b'__version__ = "1.0.1"'


def test_never_synced_and_different_asks_first(tmp_path, monkeypatch):
    fake = FakeGitHub({"run.py": b"github version"})
    _write(str(tmp_path), "run.py", "my version")
    with pytest.raises(gs.Conflict):
        _pipeline(tmp_path, monkeypatch, fake)._push_source()
    assert fake.files()["run.py"] == b"github version"   # nothing overwritten


def test_ignore_rules():
    pats = gs.ALWAYS_SKIP + ["build/", "dist/", "*.spec.bak"]
    assert gs.ignored("build/x/y.txt", pats) and gs.ignored("xmlray/__pycache__/a.pyc", pats)
    assert not gs.ignored("builder/release_manager.py", pats)
    assert gs.ignored("dist/installer/XML-ray-Setup-1.0.0.exe", pats)
    assert gs.ignored(".builder_sync.json", pats)
