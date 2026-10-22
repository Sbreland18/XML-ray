"""Code signing for the Release Manager (Windows signtool.exe). Ported from GAMbit.

Three ways to sign, matching how certificates are usually delivered:
  pfx    – a certificate file (.pfx/.p12) and its password (OV certificates)
  store  – a certificate in the Windows certificate store, picked by its
           SHA-1 thumbprint (EV certificates on a USB token / cloud HSM)
  azure  – Microsoft Azure Trusted Signing (Artifact Signing), using the
           Azure.CodeSigning.Dlib.dll and a metadata.json file

Inno Setup signs the installer *and* its uninstaller when it is given a
"sign tool" command (ISCC /S<name>=<command>, plus SignTool= in the .iss).
"""

from __future__ import annotations

import glob
import os
import shutil

DEFAULT_TIMESTAMP = {"pfx": "http://timestamp.digicert.com",
                     "store": "http://timestamp.digicert.com",
                     "azure": "http://timestamp.acs.microsoft.com"}


def find_signtool() -> str:
    found = shutil.which("signtool")
    if found:
        return found
    roots = [os.path.expandvars(r"%ProgramFiles(x86)%\Windows Kits\10\bin"),
             os.path.expandvars(r"%ProgramFiles%\Windows Kits\10\bin")]
    hits = []
    for r in roots:
        hits += glob.glob(os.path.join(r, "10.*", "x64", "signtool.exe"))
    return sorted(hits)[-1] if hits else ""


def sign_args(o: dict) -> list[str]:
    """signtool arguments (without the file) for the chosen method."""
    mode = o.get("mode", "off")
    ts = o.get("timestamp") or DEFAULT_TIMESTAMP.get(mode, "")
    args = ["sign", "/fd", "SHA256"]
    if ts:
        args += ["/tr", ts, "/td", "SHA256"]
    if mode == "pfx":
        if not o.get("pfx") or not os.path.isfile(o["pfx"]):
            raise RuntimeError("Choose the certificate file (.pfx) to sign with.")
        args += ["/f", o["pfx"]]
        if o.get("password"):
            args += ["/p", o["password"]]
    elif mode == "store":
        thumb = (o.get("thumbprint") or "").replace(" ", "")
        if len(thumb) != 40:
            raise RuntimeError("Paste the certificate's 40-character SHA-1 thumbprint.")
        args += ["/sha1", thumb]
    elif mode == "azure":
        if not o.get("dlib") or not os.path.isfile(o["dlib"]):
            raise RuntimeError("Choose Azure.CodeSigning.Dlib.dll (from the Trusted Signing "
                               "client tools).")
        if not o.get("metadata") or not os.path.isfile(o["metadata"]):
            raise RuntimeError("Choose the metadata.json with your Trusted Signing account "
                               "and certificate profile.")
        args += ["/dlib", o["dlib"], "/dmdf", o["metadata"]]
    else:
        raise RuntimeError("Signing is off.")
    if o.get("description"):
        args += ["/d", o["description"]]
    return args


def masked(args: list[str]) -> list[str]:
    """Hide the pfx password when logging."""
    out, hide = [], False
    for a in args:
        out.append("********" if hide else a)
        hide = a == "/p"
    return out


def inno_sign_switch(signtool: str, o: dict, name: str = "xmlraysign") -> str:
    """ISCC switch that defines the sign tool Inno uses for setup + uninstaller."""
    def esc(a):
        a = a.replace("$", "$$")
        return f"$q{a}$q" if (" " in a or "\\" in a or '"' in a) else a
    parts = [f"$q{signtool}$q"] + [esc(a) for a in sign_args(o)] + ["$q$f$q"]
    return f"/S{name}=" + " ".join(parts)
