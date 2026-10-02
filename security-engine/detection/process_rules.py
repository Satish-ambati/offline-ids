"""Behavioural assessment of a new process. A filename alone never makes a process suspicious."""
import ntpath

UNUSUAL_DIR_MARKERS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\downloads\\", "\\users\\public\\",
                       "\\programdata\\", "\\$recycle.bin\\", "\\appdata\\roaming\\", "\\perflogs\\")
TRUSTED_PREFIXES = ("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\")
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "acrobat.exe"}
SCRIPT_CHILDREN = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                   "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
SYSTEM_BINARIES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe"}


def assess_process(name: str, exe: str, parent_name: str) -> list[dict]:
    """Return a list of {kind, text} behavioural reasons (empty list = nothing unusual)."""
    reasons: list[dict] = []
    n = (name or "").lower()
    e = (exe or "").lower().replace("/", "\\")
    p = (parent_name or "").lower()
    if e and not e.startswith(TRUSTED_PREFIXES) and any(m in e for m in UNUSUAL_DIR_MARKERS):
        reasons.append({"kind": "unusual_path", "text": f"Executable launched from a user-writable location: {exe}"})
    if n in SYSTEM_BINARIES and e and not e.startswith("c:\\windows\\system32\\"):
        reasons.append({"kind": "unusual_path",
                        "text": f"{name} normally lives in System32 but runs from {ntpath.dirname(exe)}"})
    if p in OFFICE_PARENTS and n in SCRIPT_CHILDREN:
        reasons.append({"kind": "parent_child_anomaly",
                        "text": f"{parent_name} spawned {name} (document apps rarely start script hosts)"})
    return reasons
