# XML-ray

**See through your DMARC reports.**

XML-ray opens the DMARC aggregate reports that Gmail, Outlook, Yahoo and others email you,
and turns them into a plain-English action plan: what's broken, what's spoofing you, and what
to fix first. Reports are read on your computer and never uploaded anywhere.

## What it does

- Opens `.xml`, `.xml.gz`, `.zip` and `.eml` report files, or a whole folder at once (drag and drop works).
- Gives your domain a health grade (A to F) based on how much legitimate mail passes and how strong your policy is.
- Builds a prioritised **Action plan**: Critical, High, Medium, Low, plus what's going well, each with step-by-step fixes.
- Recognises common services (Google, Microsoft 365, SendGrid, Mailchimp, Amazon SES, and more) and explains why each one passes or fails.
- Exports a shareable HTML summary or a CSV of every sender.
- Updates itself from GitHub Releases.

## Project layout

```
run.py                       Entry point
xmlray/
  parser.py                  Reads reports (xml / gz / zip / eml), safely
  analyzer.py                Findings, priorities and health score
  senders.py                 Known-service detection and reverse DNS
  updater.py                 GitHub Releases update check, download, SHA-256 verify
  export.py                  HTML summary and CSV export
  ui/                        PySide6 interface
  assets/                    Icon and sample report
builder/release_manager.py   GUI that builds the installer and publishes releases
packaging/XML-ray.spec       PyInstaller recipe
packaging/installer.iss      Inno Setup installer script
tests/                       pytest tests
```

## One-time setup (your build PC)

1. Install **Python 3.11+ (64-bit)**, **Git**, and **Inno Setup 6.3+** (https://jrsoftware.org/isdl.php).
2. Create the repository `Sbreland18/XML-ray` on GitHub. Keep it **public**: installed copies
   check `releases/latest` without a login, which doesn't work for private repos.
3. Push this project to it:
   ```
   git init
   git add .
   git commit -m "Initial XML-ray"
   git branch -M main
   git remote add origin https://github.com/Sbreland18/XML-ray.git
   git push -u origin main
   ```
4. Double-click **Run XML-ray.bat** or **Release Manager.bat**. The first time, it creates a
   private Python environment in `.venv` and installs everything it needs (a few minutes).
5. Create a GitHub token: Settings → Developer settings → Fine-grained tokens → limit it to the
   `XML-ray` repository → Repository permissions → **Contents: Read and write**.

Try the app with **Run XML-ray.bat**, then click **Try a sample report**.

## Releasing an update

Double-click **Release Manager.bat** in the project folder.

1. Pick the new version (**+ Fix**, **+ Feature** or **+ Major**).
2. Write release notes. Users see them in the update prompt. **Fill in from Git commits** drafts them for you.
3. Paste your token (tick *Remember* to keep it in Windows Credential Manager) and click **Test**.
4. Click **Build and publish**.

The Release Manager then: writes the version into `xmlray/__version__.py` → builds with PyInstaller
→ creates `dist/installer/XML-ray-Setup-<version>.exe` with Inno Setup → writes a SHA-256 checksum
→ uploads your changed source files to GitHub → creates the GitHub release → uploads the
installer and checksum.

### Source code sync (no Git needed)

Git isn't required. The Release Manager uploads your source code straight to GitHub using your
token (the same approach as GAMbit's builder), as one commit per release. It only uploads files
that changed, and it skips `dist`, `build`, `.venv` and anything in `.gitignore`.

- **Empty repository:** your files become its first version when you publish.
- **Get latest from GitHub** downloads changes made on github.com or on another PC. Your own
  edits are kept, and any file that gets replaced is backed up to `_sync_backup` first.
- **Files changed in both places:** you're asked whether to keep yours or use GitHub's.
- **Safety:** if someone else uploaded changes since your last sync, publishing stops and asks
  you to get the latest first, so nothing on GitHub is overwritten by surprise.
- Sync state is remembered in `.builder_sync.json` (don't delete it).

If the folder is a Git clone, you can choose **Commit and push with Git** instead.

**Build installer** alone is useful for testing before you publish. **Draft** and
**Pre-release** releases are never offered to users.

## How users get updates

On start-up (and from *Help → Check for updates*) XML-ray asks GitHub for the latest release.
If it's newer, the user sees the release notes and can **Install and restart**: XML-ray downloads
the installer, verifies its SHA-256 checksum, runs it silently, and reopens on the new version.
The installer is per-user by default, so no admin prompt appears. Users can skip a version or
turn off start-up checks under *Settings*.

## Good to know

- **SmartScreen:** unsigned installers show “Windows protected your PC” on first download. To
  remove it, buy a code-signing certificate and sign `XML-ray.exe` and the installer with
  `signtool` (Inno Setup's `SignTool=` directive can do this during the build).
- **Reverse DNS** lookups name the sending servers. Turn them off under *Settings* if your network blocks them.
- Run tests with `python -m pytest tests`.
