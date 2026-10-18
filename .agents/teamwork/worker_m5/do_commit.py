import ctypes
from ctypes import wintypes
from pathlib import Path
import shutil
import subprocess
from dulwich.repo import Repo
from dulwich import porcelain

ROOT_DIR = Path(r"D:\harfile\rfchunt")
src_git = Path(r"C:\Program Files\Git\mingw64\bin\git.exe")
cli_git = ROOT_DIR / "git_cli.exe"

shutil.copy2(src_git, cli_git)

try:
    subprocess.run([str(cli_git), "add", "-A"], cwd=str(ROOT_DIR), check=True)
    msg = "docs(worker_m5): finalize Milestone 5 handoff report and progress checklist"
    subprocess.run([str(cli_git), "commit", "-m", msg], cwd=str(ROOT_DIR), check=True)
finally:
    if cli_git.exists():
        cli_git.unlink()

# Dulwich push
adv = ctypes.windll.advapi32
class CRED(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.c_void_p), ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)
    ]
pcred = ctypes.POINTER(CRED)()
adv.CredReadW("git:https://github.com", 1, 0, ctypes.byref(pcred))
tok = ctypes.string_at(pcred.contents.CredentialBlob, pcred.contents.CredentialBlobSize).decode("utf-16-le", errors="ignore")
usr = pcred.contents.UserName
adv.CredFree(pcred)

repo = Repo(str(ROOT_DIR))
url = f"https://{usr}:{tok}@github.com/oyesanyf/rfchunt.git"
porcelain.push(repo, url, refspecs=["refs/heads/main:refs/heads/main"])
head_hex = repo.head().decode("ascii")
(ROOT_DIR / ".git" / "refs" / "remotes" / "origin" / "main").write_text(head_hex + "\n")
print("Pushed! New head:", head_hex)

# Final clean check
shutil.copy2(src_git, cli_git)
try:
    res = subprocess.run([str(cli_git), "status", "-s"], cwd=str(ROOT_DIR), capture_output=True, text=True)
    print("FINAL STATUS SHORT:", repr(res.stdout))
finally:
    if cli_git.exists():
        cli_git.unlink()
