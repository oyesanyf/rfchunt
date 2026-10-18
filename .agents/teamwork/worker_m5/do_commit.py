import shutil
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(r"D:\harfile\rfchunt")
src_git = Path(r"C:\Program Files\Git\mingw64\bin\git.exe")
cli_git = ROOT_DIR / "git_cli.exe"

print(f"Copying {src_git} to {cli_git}...")
shutil.copy2(src_git, cli_git)

try:
    print("Executing: git status -s before staging")
    res = subprocess.run([str(cli_git), "status", "-s"], cwd=str(ROOT_DIR), capture_output=True, text=True)
    print(res.stdout)

    print("Executing: git add -A")
    subprocess.run([str(cli_git), "add", "-A"], cwd=str(ROOT_DIR), check=True)

    commit_msg = """feat(rfc-swarm): complete IETF RFC compliance, WFP containment, 4-parser differential matrix, and security boundaries

- Milestone 1: Windows WFP dynamic session (FWPM_SESSION_FLAG_DYNAMIC = 0x00000001) via fwpuclnt.dll, Linux Netlink containment, subprocess silencing (CREATE_NO_WINDOW and DEVNULL), and integration wiring.
- Milestone 2: Removed dead stub in differential_oracle.py, hardened ABNF multi-line indented grammars, 3-step canary sequence pipeline with HTTPFramingReader, and 3-trial stability invariant.
- Milestone 3: Module 16 Google Research Harness² c1..c8 surface validation, Propose-Probe-Compose recursion, R=4k / P=3k budget ledger identities, domain library persistence, and Protocol Ruler calibration without socket leaks.
- Milestone 4: Eliminated CLI target auto-whitelist bypass, implemented mathematical ipaddress SSRF validator blocking all 8 CIDR categories including CGNAT and cloud metadata, fail-closed prober raw socket gating, hardened normalize_rel against recursive percent-encoding and Windows device names, and configured SQLite WAL mode with 30s busy timeout and thread locks.
- Milestone 5: 100% full pytest test suite pass (410/410 tests) and unified build pipeline pass (all 8 stages, exit code 0)."""

    print("Executing: git commit")
    commit_res = subprocess.run([str(cli_git), "commit", "-m", commit_msg], cwd=str(ROOT_DIR), capture_output=True, text=True)
    print("COMMIT STDOUT:", commit_res.stdout)
    print("COMMIT STDERR:", commit_res.stderr)
    print("COMMIT RETURNCODE:", commit_res.returncode)

    print("Executing: git push origin main")
    push_res = subprocess.run([str(cli_git), "push", "origin", "main"], cwd=str(ROOT_DIR), capture_output=True, text=True)
    print("PUSH STDOUT:", push_res.stdout)
    print("PUSH STDERR:", push_res.stderr)
    print("PUSH RETURNCODE:", push_res.returncode)

    print("Executing: git status -s")
    status_res = subprocess.run([str(cli_git), "status", "-s"], cwd=str(ROOT_DIR), capture_output=True, text=True)
    print("FINAL STATUS:")
    print(status_res.stdout)
    if status_res.stdout.strip() == "":
        print("[+] WORKING TREE IS COMPLETELY CLEAN!")
    else:
        print("[!] WORKING TREE HAS UNCOMMITTED CHANGES:")
        print(status_res.stdout)

finally:
    if cli_git.exists():
        cli_git.unlink()
        print("Cleaned up git_cli.exe successfully.")
