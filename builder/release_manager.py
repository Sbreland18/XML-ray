"""XML-ray Release Manager.

Builds the Windows installer and publishes it as a GitHub release that the installed app
picks up automatically. Run from the project folder:

    python builder/release_manager.py

Needs (developer machine only): Python with requirements-dev.txt installed, Inno Setup 6.3+,
and a GitHub token with Contents: Read and write access. Git is NOT needed: source code is
uploaded with the GitHub API (builder/github_sync.py). Git is used only if this folder is
already a Git clone and you choose it.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import requests
from PySide6.QtCore import QSettings, Qt, QThread, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFont, QIcon, QTextCursor
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QFrame, QGroupBox, QHBoxLayout, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSplitter,
    QVBoxLayout, QWidget,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from xmlray.config import APP_NAME, GITHUB_OWNER, GITHUB_REPO, INSTALLER_PREFIX  # noqa: E402
from xmlray.ui.style import STYLESHEET, light_palette  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import github_sync  # noqa: E402  (builder/github_sync.py)
import signing  # noqa: E402  (builder/signing.py)

try:
    import keyring
except ImportError:  # pragma: no cover
    keyring = None

VERSION_FILE = ROOT / "xmlray" / "__version__.py"
SPEC_FILE = ROOT / "packaging" / "XML-ray.spec"
ISS_FILE = ROOT / "packaging" / "installer.iss"
DIST = ROOT / "dist"
INSTALLER_DIR = DIST / "installer"
KEYRING_SERVICE = "XML-ray-ReleaseManager"
API = "https://api.github.com"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


# ------------------------------------------------------------------- helpers

def read_version() -> str:
    m = re.search(r'__version__\s*=\s*"([^"]+)"', VERSION_FILE.read_text(encoding="utf-8"))
    return m.group(1) if m else "0.0.0"


def write_version(version: str) -> None:
    VERSION_FILE.write_text(f'__version__ = "{version}"\n', encoding="utf-8")


def bump(version: str, part: str) -> str:
    major, minor, patch = (int(x) for x in version.split("."))
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def version_tuple(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0, 0, 0)


def is_git_clone() -> bool:
    return (ROOT / ".git").is_dir() and shutil.which("git") is not None


def find_iscc() -> str:
    candidates = [
        shutil.which("ISCC"),
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"),
    ]
    return next((c for c in candidates if c and Path(c).is_file()), "")


def installer_path(version: str) -> Path:
    return INSTALLER_DIR / f"{INSTALLER_PREFIX}-{version}.exe"


def gh_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "XML-ray-Release-Manager",
    }


def git(*args: str) -> str:
    """Run a Git command and return its output, or "" if Git isn't installed or it fails."""
    if not shutil.which("git"):
        return ""
    try:
        out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    except OSError:
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


class ProgressFile:
    """File wrapper that reports upload progress and gives requests a Content-Length."""

    def __init__(self, path: Path, callback):
        self._fh = open(path, "rb")
        self._size = path.stat().st_size
        self._sent = 0
        self._cb = callback

    def __len__(self):
        return self._size

    def read(self, size=-1):
        chunk = self._fh.read(1024 * 1024 if size is None or size < 0 else size)
        self._sent += len(chunk)
        self._cb(self._sent, self._size)
        return chunk

    def close(self):
        self._fh.close()


# -------------------------------------------------------------------- worker

class Pipeline(QThread):
    log = Signal(str)
    stage = Signal(str)
    progress = Signal(int, int)
    succeeded = Signal(str)
    failed = Signal(str)
    conflict = Signal(list)

    def __init__(self, cfg: dict):
        super().__init__()
        self.cfg = cfg
        self.branch = ""

    # Each step raises on failure; run() reports the first error.
    def run(self):
        c = self.cfg
        try:
            if c.get("only_pull"):
                self._pull()
                self.succeeded.emit("pulled")
                return
            if c["publish"]:
                self._preflight()
            if c.get("pull_first"):
                self._pull()
                pulled = read_version()
                if version_tuple(pulled) > version_tuple(c["version"]):
                    raise RuntimeError(f"GitHub's code is already at version {pulled}. Choose a "
                                       f"higher version and try again.")
            if c["build"]:
                self._build()
            path = installer_path(c["version"])
            if not path.is_file():
                raise RuntimeError(f"Installer not found: {path}. Build it first.")
            sha = self._checksum(path)
            if not c["publish"]:
                self.succeeded.emit(f"Installer ready: {path}")
                return
            commit = ""
            if c["source"] == "git":
                self._git_push()
            elif c["source"] == "api":
                commit = self._push_source()
            elif not self._api().head(self._branch()):
                raise RuntimeError("Your GitHub repository is empty, so GitHub can't create a "
                                   "release yet. Under Source code, choose \u201cUpload my "
                                   "changed files\u201d and publish again.")
            url = self._publish(path, sha, commit)
            self.succeeded.emit(url)
        except github_sync.Conflict as exc:
            self.conflict.emit(exc.files)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))

    # GitHub source sync (no Git needed) ------------------------------------

    def _api(self) -> "github_sync.Api":
        c = self.cfg
        return github_sync.Api(f"{c['owner']}/{c['repo']}", c["token"], self.log.emit)

    def _branch(self) -> str:
        if not self.branch:
            r = requests.get(self._repo_api(), headers=gh_headers(self.cfg["token"]), timeout=20)
            if r.status_code == 200:
                self.branch = r.json().get("default_branch") or "main"
            elif r.status_code == 404:
                raise RuntimeError(f"Repository {self.cfg['owner']}/{self.cfg['repo']} wasn't "
                                   "found, or the token can't see it.")
            elif r.status_code == 401:
                raise RuntimeError("GitHub rejected the token. It may be expired or mistyped.")
            else:
                r.raise_for_status()
        return self.branch

    def _pull(self) -> None:
        self.stage.emit("Getting the latest files from GitHub")
        if not self.cfg["token"]:
            raise RuntimeError("Add a GitHub token first.")
        plan = github_sync.pull(str(ROOT), self._api(), self._branch(), log=self.log.emit,
                                conflicts=self.cfg.get("conflicts", "stop"))
        if not plan.get("empty"):
            self.log.emit(f"Updated {len(plan.get('applied', []))} file(s) from GitHub.")

    def _push_source(self) -> str:
        self.stage.emit("Uploading your source code to GitHub")
        api, branch = self._api(), self._branch()
        man = github_sync.load_manifest(str(ROOT))
        if not man.get("commit") and api.head(branch):
            # GitHub already has files but this folder has never synced: compare first so
            # nothing on GitHub is overwritten by surprise.
            self.log.emit("This folder hasn't been synced with GitHub before. Comparing first.")
            self._pull()
            self.stage.emit("Uploading your source code to GitHub")
        return github_sync.push(str(ROOT), api, branch, f"Release v{self.cfg['version']}",
                                log=self.log.emit)

    def _sh(self, cmd: list[str], show: list[str] | None = None) -> None:
        self.log.emit("> " + " ".join(f'"{x}"' if " " in x else x for x in (show or cmd)))
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0  # type: ignore[attr-defined]
        proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", creationflags=flags)
        assert proc.stdout is not None
        for line in proc.stdout:
            self.log.emit(line.rstrip())
        if proc.wait() != 0:
            raise RuntimeError(f"{Path(cmd[0]).name} failed with exit code {proc.returncode}. "
                               "See the log for details.")

    def _repo_api(self, path: str = "") -> str:
        return f"{API}/repos/{self.cfg['owner']}/{self.cfg['repo']}{path}"

    def _preflight(self) -> None:
        self.stage.emit("Checking GitHub access")
        c = self.cfg
        if not c["token"]:
            raise RuntimeError("Add a GitHub token before publishing.")
        r = requests.get(self._repo_api(), headers=gh_headers(c["token"]), timeout=20)
        if r.status_code == 404:
            raise RuntimeError(f"Repository {c['owner']}/{c['repo']} wasn't found, or the token "
                               "can't see it.")
        if r.status_code == 401:
            raise RuntimeError("GitHub rejected the token. It may be expired or mistyped.")
        r.raise_for_status()
        self.branch = r.json().get("default_branch") or "main"
        tag = f"v{c['version']}"
        r = requests.get(self._repo_api(f"/releases/tags/{tag}"), headers=gh_headers(c["token"]),
                         timeout=20)
        if r.status_code == 200:
            raise RuntimeError(f"A release tagged {tag} already exists. Choose a new version.")
        self.log.emit(f"GitHub access OK. {tag} is available.")

    def _signing(self) -> bool:
        return self.cfg.get("sign", {}).get("mode", "off") != "off"

    def _signtool(self) -> str:
        tool = self.cfg["sign"].get("signtool") or signing.find_signtool()
        if not tool or not Path(tool).is_file():
            raise RuntimeError("signtool.exe wasn't found. Install the Windows SDK (only the "
                               "“Signing Tools for Desktop Apps” part is needed) or set its path.")
        return tool

    def _sign(self, path: Path) -> None:
        args = [self._signtool(), *signing.sign_args(self.cfg["sign"]), str(path)]
        self._sh(args, show=signing.masked(args))
        self._sh([self._signtool(), "verify", "/pa", str(path)])
        self.log.emit(f"Signed {path.name}")

    def _build(self) -> None:
        c = self.cfg
        if c.get("run_tests"):
            self.stage.emit("Running the tests")
            try:
                self._sh([sys.executable, "-m", "pytest", "-q", "tests"])
            except RuntimeError:
                raise RuntimeError("Some tests failed, so nothing was built or published. "
                                   "See the log for which ones.") from None
        self.stage.emit("Writing version number")
        write_version(c["version"])
        self.log.emit(f"Set xmlray/__version__.py to {c['version']}")

        self.stage.emit("Building the app with PyInstaller")
        cmd = [sys.executable, "-m", "PyInstaller", str(SPEC_FILE), "--noconfirm",
               "--distpath", str(DIST), "--workpath", str(ROOT / "build")]
        if c["clean"]:
            cmd.append("--clean")
        self._sh(cmd)
        if self._signing():
            self.stage.emit("Signing XML-ray.exe")
            self._sign(DIST / "XML-ray" / "XML-ray.exe")

        self.stage.emit("Creating the installer with Inno Setup")
        if not c["iscc"] or not Path(c["iscc"]).is_file():
            raise RuntimeError("Inno Setup's ISCC.exe wasn't found. Install Inno Setup 6.3+ "
                               "or browse to ISCC.exe.")
        cmd = [c["iscc"], f"/DMyAppVersion={c['version']}"]
        show = list(cmd)
        if self._signing():
            tool = self._signtool()
            cmd += ["/DSIGN=1", signing.inno_sign_switch(tool, c["sign"])]
            show += ["/DSIGN=1", signing.inno_sign_switch(
                tool, {**c["sign"], "password": "********"} if c["sign"].get("password")
                else c["sign"])]
        self._sh(cmd + [str(ISS_FILE)], show=show + [str(ISS_FILE)])
        if self._signing():
            self.stage.emit("Checking the installer's signature")
            self._sh([self._signtool(), "verify", "/pa", str(installer_path(c["version"]))])

    def _checksum(self, path: Path) -> str:
        self.stage.emit("Calculating checksum")
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        digest = h.hexdigest()
        Path(str(path) + ".sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")
        self.log.emit(f"SHA-256 {digest}")
        return digest

    def _git_push(self) -> None:
        self.stage.emit("Committing and tagging with Git")
        tag = f"v{self.cfg['version']}"
        if not is_git_clone():
            raise RuntimeError("This folder isn't a Git clone (or Git isn't installed). Under "
                               "Source code, choose \u201cUpload my changed files\u201d instead.")
        self._sh(["git", "add", "-A"])
        status = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT)
        if status.returncode != 0:
            self._sh(["git", "commit", "-m", f"Release {tag}"])
        self._sh(["git", "tag", "-a", tag, "-m", f"XML-ray {tag}"])
        self._sh(["git", "push"])
        self._sh(["git", "push", "origin", tag])

    def _publish(self, path: Path, sha: str, commit: str = "") -> str:
        c = self.cfg
        self.stage.emit("Creating the GitHub release")
        tag = f"v{c['version']}"
        body = {
            "tag_name": tag,
            "name": c["title"] or f"{APP_NAME} {tag}",
            "body": c["notes"],
            "draft": c["draft"],
            "prerelease": c["prerelease"],
        }
        if c["source"] != "git":
            # tag the commit we just uploaded (or the tip of the default branch)
            body["target_commitish"] = commit or self._branch()
        r = requests.post(self._repo_api("/releases"), json=body,
                          headers=gh_headers(c["token"]), timeout=30)
        if r.status_code >= 300:
            message = r.json().get("message", r.text)
            if "empty" in message.lower():
                raise RuntimeError(
                    "Your GitHub repository is empty, and GitHub can't create a release in an "
                    "empty repository. On github.com, open the repository and click "
                    "\"Add file\" > \"Upload files\" (or create a README), commit it, then click "
                    "\"Publish existing build\" here.")
            raise RuntimeError(f"GitHub couldn't create the release ({r.status_code}): {message}")
        release = r.json()
        upload_base = release["upload_url"].split("{", 1)[0]
        self.log.emit(f"Created release {tag} (id {release['id']})")

        for asset in (path, Path(str(path) + ".sha256")):
            self.stage.emit(f"Uploading {asset.name}")
            pf = ProgressFile(asset, lambda d, t: self.progress.emit(d, t))
            try:
                headers = gh_headers(c["token"]) | {"Content-Type": "application/octet-stream"}
                up = requests.post(upload_base, params={"name": asset.name}, data=pf,
                                   headers=headers, timeout=600)
            finally:
                pf.close()
            if up.status_code >= 300:
                raise RuntimeError(f"Upload of {asset.name} failed ({up.status_code}): "
                                   f"{up.text[:300]}")
            self.log.emit(f"Uploaded {asset.name}")
        return release["html_url"]


# -------------------------------------------------------------------- window

class ReleaseManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("XML-ray", "ReleaseManager")
        self.worker: Pipeline | None = None
        self.setWindowTitle("XML-ray Release Manager")
        self.resize(1080, 760)

        root = QWidget(objectName="Page")
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        header = QFrame(objectName="Header")
        h = QHBoxLayout(header)
        h.setContentsMargins(20, 12, 20, 12)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        titles.addWidget(QLabel("Release Manager", objectName="AppTitle"))
        titles.addWidget(QLabel("Build the XML-ray installer and publish it to GitHub",
                                objectName="AppTagline"))
        h.addLayout(titles)
        h.addStretch(1)
        open_rel = QPushButton("Open releases page")
        open_rel.clicked.connect(lambda: QDesktopServices.openUrl(
            QUrl(f"https://github.com/{self.owner.text()}/{self.repo.text()}/releases")))
        h.addWidget(open_rel)
        outer.addWidget(header)

        split = QSplitter(Qt.Horizontal)
        form_scroll = QScrollArea()
        form_scroll.setWidgetResizable(True)
        form_scroll.setFrameShape(QFrame.NoFrame)
        form_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        form_scroll.setWidget(self._build_form())
        split.addWidget(form_scroll)
        split.addWidget(self._build_log())
        split.setSizes([520, 560])
        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(16, 16, 16, 16)
        bl.addWidget(split)
        outer.addWidget(body, 1)
        self.setCentralWidget(root)
        self._load_settings()

    # form ---------------------------------------------------------------

    def _build_form(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 12, 0)
        lay.setSpacing(12)

        ver = QGroupBox("Version")
        f = QFormLayout(ver)
        self.current_label = QLabel(read_version())
        f.addRow("Current version", self.current_label)
        row = QHBoxLayout()
        self.version = QLineEdit(bump(read_version(), "patch"))
        self.version.setFixedWidth(100)
        row.addWidget(self.version)
        for part, label in (("patch", "Fix"), ("minor", "Feature"), ("major", "Major")):
            b = QPushButton(f"+ {label}")
            b.setToolTip({"patch": "Bug fixes: 1.0.0 → 1.0.1",
                          "minor": "New features: 1.0.0 → 1.1.0",
                          "major": "Big changes: 1.0.0 → 2.0.0"}[part])
            b.clicked.connect(lambda _=False, p=part: self.version.setText(bump(read_version(), p)))
            row.addWidget(b)
        row.addStretch(1)
        f.addRow("New version", row)
        lay.addWidget(ver)

        rel = QGroupBox("Release notes")
        v = QVBoxLayout(rel)
        self.title = QLineEdit()
        self.title.setPlaceholderText("Title (default: XML-ray v1.2.3)")
        v.addWidget(self.title)
        self.notes = QPlainTextEdit()
        self.notes.setPlaceholderText("What changed? Users see this text in the update prompt. "
                                      "Markdown works.")
        v.addWidget(self.notes, 1)
        gen = QPushButton("Fill in from Git commits since the last release")
        gen.clicked.connect(self.notes_from_git)
        v.addWidget(gen)
        lay.addWidget(rel, 1)

        gh = QGroupBox("GitHub")
        g = QFormLayout(gh)
        repo_row = QHBoxLayout()
        self.owner = QLineEdit(GITHUB_OWNER)
        self.repo = QLineEdit(GITHUB_REPO)
        repo_row.addWidget(self.owner)
        repo_row.addWidget(QLabel("/"))
        repo_row.addWidget(self.repo)
        g.addRow("Repository", repo_row)
        tok_row = QHBoxLayout()
        self.token = QLineEdit()
        self.token.setEchoMode(QLineEdit.Password)
        self.token.setPlaceholderText("github_pat_… (Contents: read and write)")
        tok_row.addWidget(self.token, 1)
        test = QPushButton("Test")
        test.clicked.connect(self.test_token)
        tok_row.addWidget(test)
        g.addRow("Token", tok_row)
        self.remember = QCheckBox("Remember token in Windows Credential Manager")
        self.remember.setEnabled(keyring is not None)
        g.addRow("", self.remember)
        self.draft = QCheckBox("Save as draft (users won't see it until you publish it on GitHub)")
        self.prerelease = QCheckBox("Mark as pre-release (users won't be offered it)")
        for cb in (self.draft, self.prerelease):
            g.addRow("", cb)
        lay.addWidget(gh)

        src = QGroupBox("Source code")
        sv = QVBoxLayout(src)
        self.source = QComboBox()
        self.source.addItem("Upload my changed files to GitHub (no Git needed)", "api")
        self.source.addItem("Commit and push with Git", "git")
        self.source.addItem("Don't upload source code, only the installer", "none")
        if not is_git_clone():
            self.source.model().item(1).setEnabled(False)
            self.source.setItemText(1, "Commit and push with Git (this folder isn't a Git clone)")
        self.source.setToolTip("Your code is uploaded before the release is created, so the "
                               "release always matches the code on GitHub.")
        sv.addWidget(self.source)
        self.pull_first = QCheckBox("Before building, get the latest files from GitHub")
        self.pull_first.setToolTip("Useful if you edit XML-ray on more than one PC, or edit files "
                                   "on github.com. Your own changes are kept, and anything "
                                   "replaced is backed up to _sync_backup first.")
        sv.addWidget(self.pull_first)
        sync_row = QHBoxLayout()
        self.sync_state = QLabel()
        self.sync_state.setWordWrap(True)
        self.sync_state.setStyleSheet("color:#5B7083;")
        sync_row.addWidget(self.sync_state, 1)
        self.btn_pull = QPushButton("Get latest from GitHub")
        self.btn_pull.clicked.connect(self.pull_now)
        sync_row.addWidget(self.btn_pull)
        sv.addLayout(sync_row)
        lay.addWidget(src)

        tools = QGroupBox("Build tools")
        t = QFormLayout(tools)
        iscc_row = QHBoxLayout()
        self.iscc = QLineEdit(find_iscc())
        browse = QPushButton("Browse")
        browse.clicked.connect(self.browse_iscc)
        iscc_row.addWidget(self.iscc, 1)
        iscc_row.addWidget(browse)
        t.addRow("Inno Setup (ISCC.exe)", iscc_row)
        self.clean = QCheckBox("Clean build (slower, avoids stale files)")
        self.clean.setChecked(True)
        t.addRow("", self.clean)
        self.run_tests = QCheckBox("Run the tests first, and stop if any fail")
        self.run_tests.setChecked(True)
        t.addRow("", self.run_tests)
        lay.addWidget(tools)

        sign = QGroupBox("Code signing (removes the Windows “unknown publisher” warning)")
        sf = QFormLayout(sign)
        self.sign_mode = QComboBox()
        for label, val in (("Don't sign", "off"), ("Certificate file (.pfx)", "pfx"),
                           ("Certificate in Windows store (USB token, EV)", "store"),
                           ("Azure Trusted Signing", "azure")):
            self.sign_mode.addItem(label, val)
        sf.addRow("Method", self.sign_mode)
        self.signtool = QLineEdit(signing.find_signtool())
        self.signtool.setPlaceholderText("signtool.exe (from the Windows SDK)")
        self.pfx = QLineEdit()
        self.pfx_pass = QLineEdit()
        self.pfx_pass.setEchoMode(QLineEdit.Password)
        self.pfx_pass.setPlaceholderText("Saved in Windows Credential Manager")
        self.thumb = QLineEdit()
        self.thumb.setPlaceholderText("40-character SHA-1 thumbprint")
        self.dlib = QLineEdit()
        self.dlib.setPlaceholderText("Azure.CodeSigning.Dlib.dll")
        self.metadata = QLineEdit()
        self.metadata.setPlaceholderText("metadata.json")
        self.ts_url = QLineEdit()
        self.ts_url.setPlaceholderText("Timestamp server (leave blank for the default)")
        self._sign_rows = {}
        for key, label, field, browse in (
                ("signtool", "signtool.exe", self.signtool, "signtool.exe (signtool.exe)"),
                ("pfx", "Certificate file", self.pfx, "Certificates (*.pfx *.p12)"),
                ("password", "Certificate password", self.pfx_pass, None),
                ("thumbprint", "Thumbprint", self.thumb, None),
                ("dlib", "Dlib file", self.dlib, "Azure.CodeSigning.Dlib.dll (*.dll)"),
                ("metadata", "Metadata file", self.metadata, "metadata.json (*.json)"),
                ("timestamp", "Timestamp server", self.ts_url, None)):
            row = QWidget()
            h = QHBoxLayout(row)
            h.setContentsMargins(0, 0, 0, 0)
            h.addWidget(field, 1)
            if browse:
                b = QPushButton("Browse")
                b.clicked.connect(lambda _=False, f=field, flt=browse: self._browse_into(f, flt))
                h.addWidget(b)
            sf.addRow(label, row)
            self._sign_rows[key] = (sf.labelForField(row), row)
        hint = QLabel("A code-signing certificate is bought from a certificate authority "
                      "(for example DigiCert, Sectigo or SSL.com) or from Microsoft's "
                      "Azure Trusted Signing service.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color:#5B7083;")
        sf.addRow("", hint)
        self.sign_mode.currentIndexChanged.connect(self._sign_mode_changed)
        lay.addWidget(sign)

        buttons = QHBoxLayout()
        self.btn_build = QPushButton("Build installer")
        self.btn_publish_only = QPushButton("Publish existing build")
        self.btn_all = QPushButton("Build and publish", objectName="Primary")
        self.btn_build.clicked.connect(lambda: self.start(build=True, publish=False))
        self.btn_publish_only.clicked.connect(lambda: self.start(build=False, publish=True))
        self.btn_all.clicked.connect(lambda: self.start(build=True, publish=True))
        buttons.addWidget(self.btn_build)
        buttons.addWidget(self.btn_publish_only)
        buttons.addStretch(1)
        buttons.addWidget(self.btn_all)
        lay.addLayout(buttons)
        return w

    def _build_log(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 0, 0, 0)
        self.stage_label = QLabel("Ready.")
        self.stage_label.setStyleSheet("font-weight:600; font-size:11pt;")
        lay.addWidget(self.stage_label)
        self.bar = QProgressBar()
        self.bar.setVisible(False)
        lay.addWidget(self.bar)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        mono = QFont("Cascadia Mono")
        mono.setStyleHint(QFont.Monospace)
        mono.setPointSize(9)
        self.log.setFont(mono)
        self.log.setStyleSheet("QPlainTextEdit { background:#17324A; color:#E3EDF4; border:none; "
                               "border-radius:6px; padding:8px; }")
        self.log.setMaximumBlockCount(20000)
        lay.addWidget(self.log, 1)
        return w

    # settings -----------------------------------------------------------

    def _load_settings(self):
        s = self.settings
        self.owner.setText(s.value("owner", GITHUB_OWNER))
        self.repo.setText(s.value("repo", GITHUB_REPO))
        if s.value("iscc"):
            self.iscc.setText(s.value("iscc"))
        default_source = "git" if is_git_clone() else "api"
        idx = self.source.findData(s.value("source", default_source))
        if idx == 1 and not is_git_clone():
            idx = 0
        self.source.setCurrentIndex(max(idx, 0))
        self.pull_first.setChecked(s.value("pull_first", False, type=bool))
        self.run_tests.setChecked(s.value("run_tests", True, type=bool))
        self.sign_mode.setCurrentIndex(max(self.sign_mode.findData(s.value("sign/mode", "off")), 0))
        for key, field in (("signtool", self.signtool), ("pfx", self.pfx), ("thumbprint", self.thumb),
                           ("dlib", self.dlib), ("metadata", self.metadata), ("timestamp", self.ts_url)):
            if s.value(f"sign/{key}"):
                field.setText(s.value(f"sign/{key}"))
        if keyring is not None:
            try:
                self.pfx_pass.setText(keyring.get_password(KEYRING_SERVICE, "pfx-password") or "")
            except Exception:  # noqa: BLE001
                pass
        self._sign_mode_changed()
        self._show_sync_state()
        token = os.environ.get("GITHUB_TOKEN", "")
        if keyring is not None:
            try:
                token = keyring.get_password(KEYRING_SERVICE, "token") or token
                self.remember.setChecked(bool(keyring.get_password(KEYRING_SERVICE, "token")))
            except Exception:  # noqa: BLE001
                pass
        self.token.setText(token)

    def _save_settings(self):
        s = self.settings
        s.setValue("owner", self.owner.text().strip())
        s.setValue("repo", self.repo.text().strip())
        s.setValue("iscc", self.iscc.text().strip())
        s.setValue("source", self.source.currentData())
        s.setValue("pull_first", self.pull_first.isChecked())
        s.setValue("run_tests", self.run_tests.isChecked())
        for k, v in self.sign_opts().items():
            if k != "password":
                s.setValue(f"sign/{k}", v)
        if keyring is not None and self.pfx_pass.text():
            try:
                keyring.set_password(KEYRING_SERVICE, "pfx-password", self.pfx_pass.text())
            except Exception:  # noqa: BLE001
                pass
        if keyring is not None:
            try:
                if self.remember.isChecked() and self.token.text().strip():
                    keyring.set_password(KEYRING_SERVICE, "token", self.token.text().strip())
                elif not self.remember.isChecked():
                    keyring.delete_password(KEYRING_SERVICE, "token")
            except Exception:  # noqa: BLE001
                pass

    # actions ------------------------------------------------------------

    def _browse_into(self, field, flt):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file", field.text(), flt)
        if path:
            field.setText(path)

    def _sign_mode_changed(self):
        mode = self.sign_mode.currentData()
        visible = {"off": set(), "pfx": {"signtool", "pfx", "password", "timestamp"},
                   "store": {"signtool", "thumbprint", "timestamp"},
                   "azure": {"signtool", "dlib", "metadata", "timestamp"}}[mode]
        for key, (label, row) in self._sign_rows.items():
            label.setVisible(key in visible)
            row.setVisible(key in visible)

    def sign_opts(self) -> dict:
        return dict(mode=self.sign_mode.currentData(), signtool=self.signtool.text().strip(),
                    pfx=self.pfx.text().strip(), password=self.pfx_pass.text(),
                    thumbprint=self.thumb.text().strip(), dlib=self.dlib.text().strip(),
                    metadata=self.metadata.text().strip(), timestamp=self.ts_url.text().strip(),
                    description="XML-ray")

    def browse_iscc(self):
        path, _ = QFileDialog.getOpenFileName(self, "Find ISCC.exe", self.iscc.text(),
                                              "ISCC.exe (ISCC.exe);;Programs (*.exe)")
        if path:
            self.iscc.setText(path)

    def notes_from_git(self):
        last = git("describe", "--tags", "--abbrev=0")
        rng = f"{last}..HEAD" if last else "HEAD"
        log = git("log", rng, "--pretty=format:- %s", "--no-merges")
        if not log:
            QMessageBox.information(self, "No commits found",
                                    "Git found no new commits (or Git isn't set up in this folder).")
            return
        self.notes.setPlainText(f"## What's new\n\n{log}\n")

    def test_token(self):
        token = self.token.text().strip()
        if not token:
            QMessageBox.warning(self, "No token", "Paste a GitHub token first.")
            return
        try:
            r = requests.get(f"{API}/repos/{self.owner.text()}/{self.repo.text()}",
                             headers=gh_headers(token), timeout=20)
        except requests.RequestException as exc:
            QMessageBox.warning(self, "Couldn't reach GitHub", str(exc))
            return
        if r.status_code == 200:
            data = r.json()
            perms = data.get("permissions", {})
            vis = "private" if data.get("private") else "public"
            msg = f"The token can see {data['full_name']} ({vis})."
            if not perms.get("push"):
                msg += ("\n\nIt does NOT have write access, so publishing will fail. Give it "
                        "Contents: Read and write.")
            if data.get("private"):
                msg += ("\n\nThis repository is private. Installed copies of XML-ray can't "
                        "download updates from a private repository. Make it public, or "
                        "publish releases to a separate public repository.")
            QMessageBox.information(self, "Token works", msg)
        else:
            QMessageBox.warning(self, "Token problem",
                                f"GitHub answered {r.status_code}: {r.json().get('message', '')}")

    def _show_sync_state(self):
        man = github_sync.load_manifest(str(ROOT))
        if man.get("commit"):
            when = man.get("when", "").replace("T", " at ")[:-3]
            self.sync_state.setText(f"Last synced with GitHub on {when} "
                                    f"(commit {man['commit'][:7]}).")
        elif man.get("branch"):
            self.sync_state.setText("GitHub is empty. Your files become its first version "
                                    "when you publish.")
        else:
            self.sync_state.setText("Not synced with GitHub yet. Your files are compared with "
                                    "GitHub and uploaded when you publish.")

    def pull_now(self, conflicts: str = "stop"):
        self.start(build=False, publish=False, only_pull=True, conflicts=conflicts)

    def start(self, build: bool, publish: bool, only_pull: bool = False,
              conflicts: str = "stop"):
        version = self.version.text().strip().lstrip("vV")
        if only_pull:
            if not self.token.text().strip():
                QMessageBox.warning(self, "No token", "Paste a GitHub token first.")
                return
        elif not VERSION_RE.match(version):
            QMessageBox.warning(self, "Check the version", "Use three numbers, like 1.2.3.")
            return
        if not only_pull and publish and not self.notes.toPlainText().strip():
            if QMessageBox.question(self, "No release notes",
                                    "Publish without release notes? Users will see an empty "
                                    "“what's new” section.") != QMessageBox.Yes:
                return
        if not only_pull and build and not importlib.util.find_spec("PyInstaller"):
            QMessageBox.warning(self, "PyInstaller missing",
                                "Run: pip install -r requirements-dev.txt")
            return
        if not only_pull and publish and not self.draft.isChecked():
            if QMessageBox.question(
                    self, "Publish release",
                    f"Publish XML-ray {version} to {self.owner.text()}/{self.repo.text()}?\n\n"
                    "Everyone running XML-ray will be offered this update.") != QMessageBox.Yes:
                return

        if build and self.sign_mode.currentData() != "off":
            try:
                signing.sign_args(self.sign_opts())
            except RuntimeError as exc:
                QMessageBox.warning(self, "Code signing", str(exc))
                return
        if build and self.run_tests.isChecked() and not importlib.util.find_spec("pytest"):
            QMessageBox.warning(self, "pytest missing", "Run: pip install -r requirements-dev.txt "
                                "(Release Manager.bat does this for you).")
            return
        self._save_settings()
        cfg = dict(
            version=version, build=build, publish=publish,
            title=self.title.text().strip(), notes=self.notes.toPlainText().strip(),
            owner=self.owner.text().strip(), repo=self.repo.text().strip(),
            token=self.token.text().strip(), draft=self.draft.isChecked(),
            prerelease=self.prerelease.isChecked(), source=self.source.currentData(),
            pull_first=self.pull_first.isChecked() and not only_pull,
            only_pull=only_pull, conflicts=conflicts,
            iscc=self.iscc.text().strip(), clean=self.clean.isChecked(),
            run_tests=self.run_tests.isChecked(), sign=self.sign_opts(),
        )
        self.log.clear()
        self._set_running(True)
        self.worker = Pipeline(cfg)
        self.worker.log.connect(self._append)
        self.worker.stage.connect(self._stage)
        self.worker.progress.connect(self._progress)
        self.worker.succeeded.connect(self._ok)
        self.worker.failed.connect(self._fail)
        self.worker.conflict.connect(self._resolve)
        self.worker.start()

    def _append(self, line: str):
        self.log.appendPlainText(line)
        self.log.moveCursor(QTextCursor.End)

    def _stage(self, text: str):
        self.stage_label.setText(text + "…")
        self.bar.setRange(0, 0)
        self._append(f"\n=== {text} ===")

    def _progress(self, done: int, total: int):
        self.bar.setRange(0, 100)
        self.bar.setValue(int(done * 100 / total) if total else 0)

    def _set_running(self, on: bool):
        for b in (self.btn_build, self.btn_publish_only, self.btn_all, self.btn_pull):
            b.setEnabled(not on)
        self.bar.setVisible(on)

    def _ok(self, result: str):
        self._set_running(False)
        self.current_label.setText(read_version())
        self._show_sync_state()
        self.stage_label.setText("Done.")
        if result == "pulled":
            self.version.setText(bump(read_version(), "patch"))
            QMessageBox.information(self, "Up to date",
                                    "This folder now has the latest files from GitHub. Any "
                                    "file that was replaced is backed up in _sync_backup.")
            return
        self._append(f"\nDone: {result}")
        if result.startswith("http"):
            box = QMessageBox(self)
            box.setWindowTitle("Release published")
            box.setText(f"XML-ray {self.version.text()} is on GitHub.")
            view = box.addButton("View release", QMessageBox.AcceptRole)
            box.addButton(QMessageBox.Close)
            box.exec()
            if box.clickedButton() is view:
                QDesktopServices.openUrl(QUrl(result))
            self.version.setText(bump(read_version(), "patch"))
            self.notes.clear()
            self.title.clear()
        else:
            QMessageBox.information(self, "Build finished", result)
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(INSTALLER_DIR)))

    def _resolve(self, files: list):
        self._set_running(False)
        self._show_sync_state()
        self.stage_label.setText("Waiting for your choice.")
        shown = "\n".join(files[:15]) + ("\n…" if len(files) > 15 else "")
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Question)
        box.setWindowTitle("Files changed in both places")
        box.setText(f"{len(files)} file(s) are different here and on GitHub. Which version "
                    "should be kept?")
        box.setInformativeText(shown)
        mine = box.addButton("Keep mine (upload them)", QMessageBox.AcceptRole)
        theirs = box.addButton("Use GitHub's (back mine up)", QMessageBox.DestructiveRole)
        box.addButton(QMessageBox.Cancel)
        box.exec()
        if box.clickedButton() is mine:
            self.pull_now("mine")
        elif box.clickedButton() is theirs:
            self.pull_now("theirs")
        else:
            self._append("\nStopped: nothing was changed.")
            return
        self._append("When that finishes, click your build or publish button again.")

    def _fail(self, error: str):
        self._set_running(False)
        self._show_sync_state()
        self.stage_label.setText("Stopped.")
        self._append(f"\nERROR: {error}")
        QMessageBox.critical(self, "Release stopped", error)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setPalette(light_palette())
    app.setStyleSheet(STYLESHEET)
    app.setWindowIcon(QIcon(str(ROOT / "xmlray" / "assets" / "icon.png")))
    w = ReleaseManager()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
