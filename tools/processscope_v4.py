#!/usr/bin/env python3
"""
ProcessScope v0.4
Linux Runtime Analysis Framework

Large attacker-oriented reconnaissance console.

Examples:
  ./processscope_v0_3.py /bin/echo
  ./processscope_v0_3.py --runtime ./target
  ./processscope_v0_3.py --trace ./target
  ./processscope_v0_3.py --proc 1234
  ./processscope_v0_3.py --proc 1234 --deep
  ./processscope_v0_3.py --json report.json ./target
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

RESET="\033[0m"; CYAN="\033[1;36m"; GREEN="\033[1;32m"
RED="\033[1;31m"; YELLOW="\033[1;33m"; MAGENTA="\033[1;35m"
WHITE="\033[1;37m"; DIM="\033[2m"; BLUE="\033[1;34m"

BANNER = r"""
██████╗ ██████╗  ██████╗  ██████╗███████╗███████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔══██╗██╔════╝
██████╔╝██████╔╝██████╔╝██║     █████╗  ███████╗███████╗██║   ██║██████╔╝██████╔╝█████╗
██╔═══╝ ██╔══██╗██╔══██╗██║     ██╔══╝  ╚════██║╚════██║██║   ██║██╔═══╝ ██╔═══╝ ██╔══╝
██║     ██║  ██║██║  ██║╚██████╗███████╗███████║███████║╚██████╔╝██║     ██║     ███████╗
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝     ╚══════╝

                 LINUX RUNTIME ANALYSIS FRAMEWORK
                    v0.4 • VULNERABILITY RESEARCH CONSOLE
"""

def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except FileNotFoundError:
        return "", f"{cmd[0]} not installed", 127
    except subprocess.TimeoutExpired:
        return "", "timeout", 124
    except Exception as e:
        return "", str(e), 1

def read(path):
    try:
        return Path(path).read_text(errors="replace")
    except Exception:
        return ""

def read_bytes(path):
    try:
        return Path(path).read_bytes()
    except Exception:
        return b""

def sec(title):
    print(f"\n{CYAN}╔══ {title} {'═' * max(3, 72-len(title))}{RESET}")

def row(k, v, width=28):
    print(f"  {WHITE}{k:<{width}}{RESET} {v}")

def ok(x):
    return f"{GREEN}YES{RESET}" if x else f"{RED}NO{RESET}"

def warn(x):
    return f"{YELLOW}{x}{RESET}"

def exists(x):
    return shutil.which(x) is not None

def save_json(path, data):
    try:
        Path(path).write_text(json.dumps(data, indent=2))
        print(f"\n{GREEN}[+] Report saved:{RESET} {path}")
    except Exception as e:
        print(f"\n{RED}[!] JSON export failed:{RESET} {e}")

def elf_report(path):
    data = {"target": str(path), "static": {}, "segments": [], "imports": [],
            "dependencies": [], "mitigations": {}, "sections": []}

    sec("01  ELF IDENTITY")
    f, _, _ = run(["file", "-L", str(path)])
    h, _, rc = run(["readelf", "-W", "-h", str(path)])
    row("Target", path)
    row("Size", f"{path.stat().st_size:,} bytes")
    row("File type", f.strip())

    if rc != 0:
        row("ELF", "unreadable")
        return data

    def field(label):
        m = re.search(rf"^\s*{re.escape(label)}:\s*(.+)$", h, re.M)
        return m.group(1).strip() if m else "unknown"

    fields = {
        "Type": field("Type"),
        "Machine": field("Machine"),
        "Entry": field("Entry point address"),
        "ProgramHeaders": field("Number of program headers"),
        "SectionHeaders": field("Number of section headers"),
    }
    data["static"] = fields
    for k, v in fields.items():
        row(k, v)

    ph, _, _ = run(["readelf", "-W", "-l", str(path)])

    sec("02  PROGRAM HEADERS → MEMORY")
    interp = re.search(r"\[Requesting program interpreter:\s*([^\]]+)\]", ph)
    row("PT_INTERP", interp.group(1) if interp else "none / static")

    for line in ph.splitlines():
        m = re.match(
            r"\s*(LOAD|DYNAMIC|INTERP|TLS|GNU_STACK|GNU_RELRO)\s+"
            r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"
            r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([RWE ]+)", line)
        if not m:
            continue
        typ, off, va, pa, fs, ms, flags = m.groups()
        rec = {"type":typ, "offset":off, "vaddr":va, "paddr":pa,
               "filesz":fs, "memsz":ms, "flags":flags.strip()}
        data["segments"].append(rec)
        if typ == "LOAD":
            risk = f" {RED}RWX MEMORY!{RESET}" if "R" in flags and "W" in flags and "E" in flags else ""
            row("PT_LOAD", f"file=0x{fs} mem=0x{ms} vaddr=0x{va} {flags.strip()}{risk}")
        elif typ in ("GNU_STACK", "GNU_RELRO"):
            row(typ, f"flags={flags.strip()} off=0x{off}")

    dyn, _, _ = run(["readelf", "-W", "-d", str(path)])
    needed = re.findall(r"\(NEEDED\).*?: \[([^\]]+)\]", dyn)
    data["dependencies"] = needed

    sec("03  DYNAMIC LINKING / DEPENDENCY GRAPH")
    row("Interpreter", interp.group(1) if interp else "none")
    row("Shared libraries", len(needed))
    for lib in needed:
        print(f"    {BLUE}↳{RESET} {lib}")

    sym, _, _ = run(["readelf", "-W", "-s", str(path)])
    imports = []
    for line in sym.splitlines():
        if " UND " in f" {line} ":
            parts = line.split()
            if parts:
                n = parts[-1]
                if n not in imports:
                    imports.append(n)
    data["imports"] = imports

    groups = {
        "Memory": ["memcpy","memmove","memset","memcmp","strcpy","strncpy","strcat",
                   "strncat","sprintf","snprintf","vsprintf","vsnprintf","scanf","sscanf"],
        "Process": ["execve","execvp","system","popen","fork","vfork","clone"],
        "Filesystem": ["open","open64","openat","creat","unlink","rename","chmod","chown"],
        "Network": ["socket","connect","bind","listen","accept","recv","recvfrom","send","sendto"],
        "Dynamic": ["dlopen","dlsym","dlclose"],
        "Privilege": ["setuid","setgid","setresuid","setresgid","capset","prctl"]
    }
    sec("04  IMPORT / ATTACK SURFACE")
    row("Imported symbols", len(imports))
    for g, names in groups.items():
        hits = [x for x in imports if any(x == n or x.startswith(n+"@") for n in names)]
        row(g, ", ".join(hits) if hits else "—")

    notes, _, _ = run(["readelf", "-W", "-n", str(path)])
    sec("05  HARDENING / MITIGATIONS")
    typ = fields["Type"]
    pie = "DYN" in typ and "shared object" not in typ.lower()
    nx = bool(re.search(r"GNU_STACK.*\bRW\b(?!E)", ph))
    relro = "GNU_RELRO" in ph
    now = "BIND_NOW" in dyn or "FLAGS.*NOW" in dyn
    canary = "__stack_chk_fail" in sym
    fortify = "_chk" in sym

    mit = {
        "PIE": pie, "NX": nx,
        "RELRO": "FULL" if relro and now else ("PARTIAL" if relro else "NO"),
        "Canary": canary, "FORTIFY": fortify,
        "SUID": bool(path.stat().st_mode & 0o4000),
        "SGID": bool(path.stat().st_mode & 0o2000)
    }
    data["mitigations"] = mit
    row("PIE", ok(pie))
    row("NX", ok(nx))
    row("RELRO", mit["RELRO"])
    row("Stack Canary", ok(canary))
    row("FORTIFY", ok(fortify))
    row("SUID", ok(mit["SUID"]))
    row("SGID", ok(mit["SGID"]))

    sec("06  IMPORTANT ELF SECTIONS")
    sh, _, _ = run(["readelf", "-W", "-S", str(path)])
    wanted = [".text",".plt",".plt.got",".got",".got.plt",".rodata",".data",
              ".bss",".dynamic",".init_array",".fini_array",".tdata",".tbss"]
    for name in wanted:
        if re.search(rf"\]\s+{re.escape(name)}\s+", sh):
            data["sections"].append(name)
            print(f"    {WHITE}{name}{RESET}")

    sec("07  STATIC CONTENT HUNT")
    strings, _, _ = run(["strings","-a","-n","6",str(path)], timeout=15)
    terms = ["password","passwd","secret","token","key","debug","admin","root",
             "config","socket","http://","https://","/tmp/","/dev/"]
    hits = []
    for s in strings.splitlines():
        if any(t in s.lower() for t in terms):
            if s not in hits:
                hits.append(s)
        if len(hits) >= 25:
            break
    row("Interesting strings", len(hits))
    for s in hits:
        print(f"    {YELLOW}{s[:120]}{RESET}")

    return data

def proc_report(pid, deep=False):
    base = Path(f"/proc/{pid}")
    data = {"pid":pid, "status":{}, "maps":[], "fds":[], "namespaces":{},
            "capabilities":{}, "limits":{}, "environment":{}}

    if not base.exists():
        print(f"{RED}[!] PID {pid} not found{RESET}")
        return data

    sec(f"08  PROCESS IDENTITY [{pid}]")
    status = read(base/"status")
    st = {}
    for line in status.splitlines():
        if ":" in line:
            k,v=line.split(":",1); st[k]=v.strip()
    data["status"] = st

    for k in ["Name","State","Pid","PPid","Threads","Uid","Gid",
              "VmSize","VmRSS","VmData","VmStk","VmExe","VmLib",
              "CapInh","CapPrm","CapEff","CapBnd","NoNewPrivs","Seccomp"]:
        if k in st: row(k, st[k])

    for name in ["exe","cwd","root"]:
        try: row(name, os.readlink(base/name))
        except Exception: row(name, "unavailable")

    cmd = read(base/"cmdline").replace("\x00"," ").strip()
    row("cmdline", cmd or "—")

    sec("09  VIRTUAL MEMORY MAP")
    maps = read(base/"maps")
    counts = {}
    regions = []
    for line in maps.splitlines():
        parts=line.split()
        if len(parts)>=5:
            perms=parts[1]
            counts[perms]=counts.get(perms,0)+1
            regions.append(line)
    data["maps"]=regions
    for perm,count in sorted(counts.items()):
        print(f"    {perm:<5} {count:>4} regions")
    row("Total VMAs", len(regions))

    if deep:
        smaps = read(base/"smaps")
        anon_rss = 0; private_dirty = 0
        for line in smaps.splitlines():
            if line.startswith("Anonymous:"):
                try: anon_rss += int(line.split()[1])
                except: pass
            elif line.startswith("Private_Dirty:"):
                try: private_dirty += int(line.split()[1])
                except: pass
        row("Anonymous memory", f"{anon_rss} kB")
        row("Private dirty", f"{private_dirty} kB")

    sec("10  FILE DESCRIPTORS / RESOURCES")
    try:
        fds=[]
        for x in sorted((base/"fd").iterdir(), key=lambda z:int(z.name)):
            try: fds.append((x.name,os.readlink(x)))
            except: pass
        data["fds"]=fds
        row("Open FDs", len(fds))
        for fd,target in fds[:35]:
            print(f"    {fd:>3} → {target}")
    except Exception as e:
        row("FD access", str(e))

    sec("11  NAMESPACES / ISOLATION")
    nsdir=base/"ns"
    try:
        for x in sorted(nsdir.iterdir()):
            try:
                target=os.readlink(x)
                data["namespaces"][x.name]=target
                print(f"    {x.name:<12} {target}")
            except: pass
    except Exception as e:
        row("Namespaces", str(e))

    sec("12  CAPABILITIES / PRIVILEGE")
    for k in ["CapInh","CapPrm","CapEff","CapBnd","NoNewPrivs","Seccomp"]:
        if k in st: row(k, st[k])
    uid = st.get("Uid","?")
    gid = st.get("Gid","?")
    row("UID", uid)
    row("GID", gid)

    sec("13  KERNEL-FACING STATE")
    for item in ["syscall","wchan","stack","sched","io"]:
        val=read(base/item).strip().replace("\n"," ")
        if val:
            row(f"/proc/{pid}/{item}", val[:180])

    sec("14  MOUNTS / CGROUPS")
    mounts=read(base/"mountinfo").splitlines()
    cgroups=read(base/"cgroup").splitlines()
    row("Mount entries", len(mounts))
    row("Cgroup entries", len(cgroups))
    if deep:
        for line in cgroups[:12]:
            print(f"    {line}")

    sec("15  NETWORK VIEW")
    for f in ["net/tcp","net/tcp6","net/udp","net/udp6","net/unix"]:
        text=read(base/f)
        if text:
            lines=text.splitlines()
            row(f"/proc/{pid}/{f}", f"{max(0,len(lines)-1)} entries")

    return data

def syscall_trace(path):
    sec("16  SYSCALL / KERNEL INTERACTION TRACE")
    if not exists("strace"):
        print(f"{RED}[!] strace not installed{RESET}")
        return {"available":False}

    cmd=["strace","-f","-qq","-tt","-T",
         "-e","trace=%file,%process,%memory,%network,%signal,%desc",
         str(path)]
    out,err,rc=run(cmd,timeout=15)
    text=err+out

    cats={
        "PROCESS":["execve(","clone(","fork(","vfork(","wait","exit_group("],
        "MEMORY":["mmap(","mprotect(","munmap(","brk(","madvise("],
        "FILES":["open(","openat(","read(","write(","close(","stat(","fstat(","access("],
        "NETWORK":["socket(","connect(","accept(","bind(","listen(","recv","send"],
        "SECURITY":["prctl(","seccomp(","setuid(","setgid("]
    }
    for cat,keys in cats.items():
        lines=[x for x in text.splitlines() if any(k in x for k in keys)]
        print(f"\n  {MAGENTA}{cat}{RESET} ({len(lines)})")
        for x in lines[:25]:
            print("    "+x)
        if len(lines)>25:
            print(f"    ... {len(lines)-25} more")

    return {"available":True,"returncode":rc,"trace":text}

def runtime_launch(path, deep=False, trace=False):
    sec("17  LIVE RUNTIME SNAPSHOT")
    print(f"  Launching: {path}")

    try:
        # Stop quickly after exec so short-lived programs don't become zombies
        # before /proc inspection. The process is resumed and cleaned up later.
        proc=subprocess.Popen([str(path)])
        time.sleep(0.08)
        try: os.kill(proc.pid, signal.SIGSTOP)
        except ProcessLookupError:
            print(f"  {YELLOW}Target exited before snapshot.{RESET}")
            return {"pid":proc.pid}

        time.sleep(0.05)
        data=proc_report(proc.pid, deep=deep)

        try: os.kill(proc.pid, signal.SIGCONT)
        except ProcessLookupError: pass
        try: proc.terminate(); proc.wait(timeout=1)
        except: 
            try: proc.kill()
            except: pass
        return data
    except Exception as e:
        print(f"  {RED}Runtime launch failed: {e}{RESET}")
        return {}


def kernel_internals(path, trace_text=""):
    sec("18  KERNEL INTERACTION / INTERNAL PATH")
    print(f"  {DIM}Static inference from ELF + observed syscalls; kernel symbols are not guessed.{RESET}")

    if trace_text:
        calls = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\(", trace_text)
        uniq=[]
        for c in calls:
            if c not in uniq: uniq.append(c)
        groups = {
            "EXEC / PROCESS": ["execve","clone","fork","vfork","wait4","exit_group"],
            "VM / MEMORY": ["mmap","mprotect","munmap","brk","madvise","mremap"],
            "FILESYSTEM": ["openat","read","write","close","stat","fstat","access","readlink"],
            "NETWORK": ["socket","connect","bind","listen","accept","recvfrom","sendto"],
            "SECURITY": ["prctl","seccomp","setuid","setgid","capget","capset"],
        }
        for group,names in groups.items():
            hits=[c for c in uniq if c in names]
            if hits:
                print(f"\n  {MAGENTA}{group}{RESET}")
                for c in hits:
                    pathmap={
                        "execve":"do_execveat_common → bprm_execve → search_binary_handler → load_elf_binary",
                        "mmap":"do_mmap → mmap_region → VM area creation / page-fault-backed mapping",
                        "mprotect":"do_mprotect_pkey → permission/VMA update",
                        "brk":"do_brk_flags → heap VMA adjustment",
                        "openat":"do_sys_openat2 → path lookup → filesystem/open handlers",
                        "read":"ksys_read → vfs_read → file-specific read operation",
                        "write":"ksys_write → vfs_write → file-specific write operation",
                        "socket":"__sys_socket → protocol-family socket creation",
                        "connect":"__sys_connect → protocol-specific connect path",
                        "prctl":"do_prctl → process security/attribute controls",
                        "seccomp":"seccomp syscall/filter machinery → syscall restriction",
                    }
                    print(f"    {c:<12} → {pathmap.get(c, 'kernel syscall implementation')}")
    else:
        print("  Run with --trace to correlate observed syscalls with kernel execution paths.")

    print(f"\n  {WHITE}Privilege boundary{RESET}")
    print("    userspace → syscall entry → kernel validation → subsystem → return to userspace")

    print(f"\n  {WHITE}High-value kernel subsystems{RESET}")
    print("    fs/          filesystem, path resolution, file objects")
    print("    mm/          virtual memory, VMAs, page faults, allocators")
    print("    kernel/      processes, syscalls, credentials, scheduling")
    print("    net/         sockets and networking")
    print("    security/    LSM, credentials, security policy")
    print("    arch/x86/    architecture-specific syscall/MMU/CPU paths")

def security_surface(path, proc_data=None):
    sec("19  VULNERABILITY RESEARCH SURFACE")
    findings=[]
    st=os.stat(path)

    if st.st_mode & 0o4000:
        findings.append(("HIGH","SUID executable","Privilege boundary / credential transition"))
    if st.st_mode & 0o2000:
        findings.append(("HIGH","SGID executable","Group privilege boundary"))

    if proc_data:
        status=proc_data.get("status",{})
        if status.get("NoNewPrivs") == "0":
            findings.append(("MED","NoNewPrivs disabled","Privilege-changing operations are not blocked by this flag"))
        if status.get("Seccomp") == "0":
            findings.append(("MED","Seccomp inactive","No seccomp mode reported for this process"))
        caps=status.get("CapEff","")
        if caps and caps != "0000000000000000":
            findings.append(("HIGH","Effective capabilities present","Process has non-zero Linux capabilities"))

    # Static mitigations are handled in elf_report; keep this section focused on attack surfaces.
    if findings:
        for sev,name,why in findings:
            color=RED if sev=="HIGH" else YELLOW
            print(f"  {color}[{sev}]{RESET} {name} — {why}")
    else:
        print(f"  {GREEN}No high-confidence privilege findings from the available static/runtime data.{RESET}")

    print("\n  Focus areas:")
    print("    memory corruption: buffers, allocators, VMAs, pointer/length handling")
    print("    logical bugs: credentials, permissions, namespaces, races, state machines")
    print("    parser attack surface: ELF, config, filesystem, network and IPC inputs")
    print("    kernel boundary: syscalls, ioctl/device interfaces, procfs/sysfs")

def main():
    ap=argparse.ArgumentParser(description="ProcessScope v0.4")
    ap.add_argument("binary",nargs="?",help="ELF binary")
    ap.add_argument("--proc",type=int,help="inspect existing PID")
    ap.add_argument("--runtime",action="store_true",help="launch and snapshot target")
    ap.add_argument("--trace",action="store_true",help="trace syscalls")
    ap.add_argument("--deep",action="store_true",help="deeper /proc and memory details")
    ap.add_argument("--json",metavar="FILE",help="export machine-readable report")
    args=ap.parse_args()

    print(f"{CYAN}{BANNER}{RESET}")

    report={"version":"0.3","timestamp":time.time()}

    if args.proc:
        report["runtime"]=proc_report(args.proc,args.deep)
        kernel_internals(None, "")
    else:
        if not args.binary:
            ap.error("provide a binary or --proc PID")
        path=Path(args.binary).expanduser().resolve()
        if not path.exists():
            print(f"{RED}[!] Target not found: {path}{RESET}")
            return 1
        print(f"  {WHITE}TARGET{RESET}  {path}")
        report["static"]=elf_report(path)
        if args.runtime:
            report["runtime"]=runtime_launch(path,args.deep,args.trace)
            security_surface(path, report.get("runtime"))
            kernel_internals(path, "")
        if args.trace:
            report["syscalls"]=syscall_trace(path)
            kernel_internals(path, report["syscalls"].get("trace",""))
            security_surface(path, report.get("runtime"))

    if args.json:
        save_json(args.json,report)

    return 0

if __name__=="__main__":
    raise SystemExit(main())
