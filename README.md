# XML-ray

**See through your DMARC reports.**

XML-ray opens the DMARC aggregate reports that Gmail, Outlook, Yahoo and others email you,
and turns them into a plain-English action plan: what's broken, what's spoofing you, and what
to fix first. Reports are read on your computer and never uploaded anywhere. Blocklists are queried
through your own network's DNS server; some lists refuse queries from large public DNS
services, which XML-ray shows as "Couldn't check" rather than "Clear".

## What it does

- **Reads your reports**: `.xml`, `.xml.gz`, `.zip`, `.json` and `.eml` files, or whole folders (drag and drop works).
- **Action plan**: problems ranked Critical, High, Medium, Low, with plain-English steps and links to each service's official setup guide. Mark items as done; they come back if newer reports show the problem is still happening.
- **Health grade** (A to F) based on how much legitimate mail passes and how strong your policy is.
- **Saved history**: every report is kept in a local database, so you only ever add new ones. Choose the period to look at (latest 7, 30 or 90 days, 12 months, or all time).
- **Trends**: a daily chart of how much email passes DMARC, for all mail or for one sender.
- **Senders**: who sends email as you, with known services recognised, the network owner and country of unknown servers (RDAP), and your own labels ("Office copier", "This is one of mine", "Ignore").
- **Live DNS check**: your current DMARC, SPF, DKIM, MX and TLS reporting records, including the SPF 10-lookup limit, report-address authorization, weak DKIM keys and missing selectors.
- **DMARC record builder**: writes the exact record for each rollout step and recommends the next one.
- **TLS reports**: reads SMTP TLS reports (TLS-RPT) to show whether email sent to you arrives encrypted.
- **Automatic import**: from an IMAP mailbox (Gmail/Google Workspace with an app password, Yahoo, iCloud, Fastmail, Zoho and others) or a watched folder.
- **Alerts**: a notification when a new unknown sender appears, a working service starts failing, or the pass rate drops.
- **"Show me how to fix this"**: for every problem, the exact DNS record to add or change (current vs new value, with copy buttons), steps for your DNS host (detected automatically: Cloudflare, GoDaddy, Namecheap, Route 53, Azure, Microsoft 365, IONOS and more), a **Check if it worked** button, and a ready-to-send email for whoever manages your DNS.
- **Road to protection**: a checklist from monitoring to p=reject that says when each enforcement step is safe (two weeks at the current step with 98% of legitimate mail passing).
- **Parked domains**: add domains that never send email and XML-ray checks they're locked down (SPF -all, DMARC reject, null MX).
- **MTA-STS and BIMI checks**, including the policy file and logo format.
- **Spam blocklist check** of your own sending servers (Spamhaus, SpamCop, Barracuda, PSBL), with removal links.
- **Lookalike domain watch**: finds registered misspellings and look-alike domains of yours and flags new ones that can send email.
- **Weekly summary email** to you or a manager.
- **Report drill-down**: double-click any report to see every row and the original file.
- **Exports**: HTML summary, PDF summary, CSV of senders.
- **Light and dark mode**, following Windows by default.
- **Updates itself** from GitHub Releases.

Reports are read on your computer and never uploaded anywhere. Blocklists are queried
through your own network's DNS server; some lists refuse queries from large public DNS
services, which XML-ray shows as "Couldn't check" rather than "Clear". The DNS check (DNS over
HTTPS via Cloudflare/Google) and the owner lookups (rdap.org) only send domain names and IP
addresses, and both can be turned off in Settings.

## Project layout

```
run.py                       Entry point (--minimized starts in the system tray)
xmlray/
  parser.py                  Reads reports (xml / gz / zip / eml / json), safely
  tlsrpt.py                  SMTP TLS report parsing and analysis
  analyzer.py                Findings, priorities, health score, trends
  storage.py                 Saved history, labels, "done" marks, alerts (SQLite)
  dnscheck.py                Live DNS health check
  rdap.py                    Network owner and country lookups
  mailimport.py              IMAP mailbox import and watched folder
  alerts.py                  Change detection for alerts
  fixguide.py                "Show me how to fix this": exact changes, DNS hosts, verification
  roadmap.py                 Road to protection checklist
  blocklist.py               Spam blocklist (DNSBL) checks
  lookalike.py               Lookalike domain watch
  mailsend.py                Weekly summary email (SMTP)
  logs.py                    Error log and diagnostics
  recordbuilder.py           DMARC record builder logic
  guides.py                  Links to each service's setup guide
  senders.py                 Known-service detection and reverse DNS
  updater.py                 GitHub Releases update check, download, SHA-256 verify
  export.py                  HTML, PDF (print layout) and CSV export
  ui/                        PySide6 interface (themes, charts, dialogs)
  assets/                    Icon and sample reports
builder/release_manager.py   GUI that builds the installer and publishes releases
builder/github_sync.py       Uploads source code to GitHub without Git
builder/signing.py           Code signing with signtool.exe
tools/make_samples.py        Regenerates the two-week sample data
packaging/                   PyInstaller recipe and Inno Setup installer script
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

Try the app with **Run XML-ray.bat**, then click **Try sample reports**.

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

The tests run first (untick **Run the tests first** to skip them); if any fail, nothing is
built or published.

**Code signing** (optional): choose a certificate file (.pfx), a certificate in the Windows
store (USB token / EV) or Azure Trusted Signing. XML-ray.exe, the installer and the
uninstaller are all signed. You need signtool.exe from the Windows SDK.

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

## Where XML-ray keeps its data

Saved reports, sender labels, "done" marks and alerts are in
`%LOCALAPPDATA%\XML-ray\history.db`. Settings are in the Windows registry under
`HKEY_CURRENT_USER\Software\XML-ray`. A mailbox password is stored in Windows Credential
Manager, never in a file. Uninstalling leaves the history in place, so reinstalling keeps it.

If something goes wrong, **Help > Save diagnostics for support** creates a zip with XML-ray's
log and settings (no reports, passwords or tokens) that users can attach to a GitHub issue.
The log itself is in `%LOCALAPPDATA%\XML-ray\logs`.
