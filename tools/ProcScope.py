#!/usr/bin/env python3
"""
ProcessScope
Linux Runtime Analysis Framework

Static ELF recon, live /proc introspection, syscall tracing, and kernel-path
notes for a target binary or an already-running PID.

Run with no flags (optionally with just a target path) to use the interactive
menu, which keeps prompting until you quit. Pass explicit flags for a single
non-interactive run that's easy to script.

Examples:
  ./processscope.py                     interactive menu
  ./processscope.py /bin/echo           interactive menu, target pre-filled
  ./processscope.py --runtime ./target
  ./processscope.py --trace ./target
  ./processscope.py --proc 1234
  ./processscope.py --proc 1234 --deep
  ./processscope.py --json report.json ./target
"""

import argparse
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import time
from pathlib import Path
import fuzzing

VERSION = "0.7"

RESET="\033[0m"; CYAN="\033[1;36m"; GREEN="\033[1;32m"
RED="\033[1;31m"; YELLOW="\033[1;33m"; MAGENTA="\033[1;35m"
WHITE="\033[1;37m"; DIM="\033[2m"; BLUE="\033[1;34m"

_LOGO = r"""
██████╗ ██████╗  ██████╗  ██████╗███████╗███████╗███████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██████╔╝██████╔╝██║   ██║██║     █████╗  ███████╗███████╗███████╗██║     ██║   ██║██████╔╝█████╗  
██╔═══╝ ██╔══██╗██║   ██║██║     ██╔══╝  ╚════██║╚════██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
██║     ██║  ██║╚██████╔╝╚██████╗███████╗███████║███████║███████║╚██████╗╚██████╔╝██║     ███████╗
╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚══════╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
""".strip("\n")

_LOGO_WIDTH = max(len(line) for line in _LOGO.splitlines())


def _build_banner():
    """Center the subtitle lines under the logo so everything lines up no
    matter how VERSION or the subtitle text changes length."""
    sub1 = "LINUX RUNTIME ANALYSIS FRAMEWORK".center(_LOGO_WIDTH)
    sub2 = f"v{VERSION}  \u2022  VULNERABILITY RESEARCH CONSOLE".center(_LOGO_WIDTH)
    return f"\n{_LOGO}\n\n{sub1}\n{sub2}\n"


BANNER = _build_banner()

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
            "exports": [], "dependencies": [], "mitigations": {}, "sections": [],
            "plt_got": [], "rpath": [], "interpreter": None}

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
        "Class": field("Class"),
        "Data": field("Data"),
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
    data["interpreter"] = interp.group(1) if interp else None
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
    data["rpath"] = re.findall(r"\((?:RPATH|RUNPATH)\).*?: \[([^\]]+)\]", dyn)

    sec("03  DYNAMIC LINKING / DEPENDENCY GRAPH")
    row("Interpreter", interp.group(1) if interp else "none")
    row("Shared libraries", len(needed))
    for lib in needed:
        print(f"    {BLUE}↳{RESET} {lib}")
    row("RPATH/RUNPATH", ":".join(data["rpath"]) or "—")

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
    exports = []
    for line in sym.splitlines():
        if " GLOBAL " in f" {line} " and " UND " not in f" {line} ":
            parts = line.split()
            if parts and parts[-1] not in exports:
                exports.append(parts[-1])
    data["exports"] = exports

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
    row("Exported symbols", len(exports))
    for g, names in groups.items():
        hits = [x for x in imports if any(x == n or x.startswith(n+"@") for n in names)]
        row(g, ", ".join(hits) if hits else "—")

    notes, _, _ = run(["readelf", "-W", "-n", str(path)])
    sec("05  HARDENING / MITIGATIONS")
    typ = fields["Type"]
    pie = "DYN" in typ and "shared object" not in typ.lower()
    nx = bool(re.search(r"GNU_STACK.*\bRW\b(?!E)", ph))
    relro = "GNU_RELRO" in ph
    now = "BIND_NOW" in dyn or bool(re.search(r"FLAGS_1\).*\bNOW\b", dyn))
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

    # Sections and relocations together expose the conventional PLT/GOT
    # surface without assuming that every architecture names it identically.
    data["plt_got"] = [name for name in data["sections"] if name.startswith(".plt") or name.startswith(".got")]
    row("PLT/GOT", ", ".join(data["plt_got"]) or "not present")

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
            "capabilities":{}, "limits":{}, "environment":{}, "memory_summary": {},
            "libraries": []}

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
    # Never print values: process environments often contain secrets.
    env = read_bytes(base/"environ").decode(errors="replace").split("\x00")
    safe_keys = [item.split("=", 1)[0] for item in env if "=" in item]
    data["environment"] = {"keys": safe_keys, "count": len(safe_keys)}
    row("Environment entries", len(safe_keys))
    if deep and safe_keys:
        print("    keys: " + ", ".join(safe_keys[:25]))

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
    wx = [line for line in regions if len(line.split()) > 1 and "w" in line.split()[1] and "x" in line.split()[1]]
    stacks = [line for line in regions if "[stack" in line]
    heaps = [line for line in regions if "[heap]" in line]
    libs = sorted({line.split()[-1] for line in regions if len(line.split()) >= 6 and ".so" in line.split()[-1]})
    data["memory_summary"] = {"writable_executable": wx, "stacks": stacks, "heaps": heaps}
    data["libraries"] = libs
    row("Writable+executable", len(wx))
    row("Stack mappings", len(stacks))
    row("Heap mappings", len(heaps))
    row("Shared libraries", len(libs))
    for mapping in wx[:8]: print(f"    {YELLOW}WX {mapping}{RESET}")

    if deep:
        smaps = read(base/"smaps")
        anon_rss = 0; private_dirty = 0
        for line in smaps.splitlines():
            if line.startswith("Anonymous:"):
                try: anon_rss += int(line.split()[1])
                except (ValueError, IndexError): pass
            elif line.startswith("Private_Dirty:"):
                try: private_dirty += int(line.split()[1])
                except (ValueError, IndexError): pass
        row("Anonymous memory", f"{anon_rss} kB")
        row("Private dirty", f"{private_dirty} kB")

    sec("10  FILE DESCRIPTORS / RESOURCES")
    try:
        fds=[]
        for x in sorted((base/"fd").iterdir(), key=lambda z:int(z.name)):
            try: fds.append((x.name,os.readlink(x)))
            except OSError: pass
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
            except OSError: pass
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
    if rc and text.strip():
        print(f"{YELLOW}[!] strace could not complete: {text.splitlines()[0]}{RESET}")

    cats={
        "PROCESS":["execve(","clone(","fork(","vfork(","wait","exit_group("],
        "MEMORY":["mmap(","mprotect(","munmap(","brk(","madvise("],
        "FILES":["open(","openat(","read(","write(","close(","stat(","fstat(","access("],
        "NETWORK":["socket(","connect(","accept(","bind(","listen(","recv","send"],
        "SECURITY":["prctl(","seccomp(","setuid(","setgid("]
    }
    summary = {}
    for cat,keys in cats.items():
        lines=[x for x in text.splitlines() if any(k in x for k in keys)]
        summary[cat.lower()] = {"count": len(lines), "samples": lines[:25]}
        print(f"\n  {MAGENTA}{cat}{RESET} ({len(lines)})")
        for x in lines[:25]:
            print("    "+x)
        if len(lines)>25:
            print(f"    ... {len(lines)-25} more")

    files = sorted(set(re.findall(r'"([^"\n]+)"', "\n".join(summary["files"]["samples"]))))
    network = summary["network"]["samples"]
    return {"available":True,"returncode":rc,"error": text if rc else None,"trace":text,"summary":summary,
            "files_accessed": files[:100], "network_activity": network}

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
        except Exception:
            try: proc.kill()
            except Exception: pass
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

def attack_surface(static_data, runtime_data=None, trace_data=None, fuzz_data=None):
    """Correlate observations, deliberately avoiding exploitability claims."""
    sec("20  ATTACK SURFACE SUMMARY")
    mit = static_data.get("mitigations", {})
    row("PIE / NX / RELRO", f"{mit.get('PIE', 'unknown')} / {mit.get('NX', 'unknown')} / {mit.get('RELRO', 'unknown')}")
    imports = static_data.get("imports", [])
    inputs = ["stdin (candidate; confirm from target behavior)", "command-line arguments", "environment"]
    if any(x.split("@", 1)[0] in {"open", "openat", "fopen", "read"} for x in imports): inputs.append("files (observed static API surface)")
    row("Input surfaces", "; ".join(inputs))
    dangerous = [x for x in imports if x.split("@", 1)[0] in {"strcpy", "strcat", "gets", "sprintf", "system", "popen", "dlopen"}]
    row("Notable imports", ", ".join(dangerous) or "none in selected set")
    if runtime_data:
        memory = runtime_data.get("memory_summary", {})
        row("Runtime WX mappings", len(memory.get("writable_executable", [])))
        row("Runtime shared libraries", len(runtime_data.get("libraries", [])))
    if trace_data and trace_data.get("available"):
        row("Observed syscalls", sum(v["count"] for v in trace_data.get("summary", {}).values()))
        row("Files observed", len(trace_data.get("files_accessed", [])))
        row("Network syscall samples", len(trace_data.get("network_activity", [])))
    tools = fuzzing.available()
    row("AFL++ available", "yes" if tools["afl-fuzz"] else "no")
    if fuzz_data:
        row("Fuzz crashes", len(fuzz_data.get("status", {}).get("crashes", [])))
    print("  Potential research areas: parser/input handling, unsafe memory APIs, privilege transitions, and unusual syscall behavior.")

MENU_ITEMS = [
    ("1", "Static ELF Recon"),
    ("2", "Runtime Process Analysis"),
    ("3", "Deep Runtime + Memory Analysis"),
    ("4", "Syscall / Kernel Interaction Trace"),
    ("5", "Full Vulnerability Research Scan"),
    ("6", "Inspect Existing PID"),
    ("7", "Full Scan + JSON Report"),
    ("q", "Quit"),
]

def _menu_box():
    """Render the menu box with its width computed from the content, so it
    stays perfectly aligned no matter how the item labels change."""
    title = "PROCESSSCOPE ANALYSIS MODE"
    rows = [f"{k}  {label}" for k, label in MENU_ITEMS]
    inner = max(len(title), *(len(r) for r in rows)) + 1

    top = f"{CYAN}┌{'─' * (inner + 2)}┐{RESET}"
    mid = f"{CYAN}├{'─' * (inner + 2)}┤{RESET}"
    bot = f"{CYAN}└{'─' * (inner + 2)}┘{RESET}"

    lines = [top, f"{CYAN}│{RESET} {WHITE}{title:<{inner}}{RESET} {CYAN}│{RESET}", mid]
    lines += [f"{CYAN}│{RESET} {line:<{inner}} {CYAN}│{RESET}" for line in rows]
    lines.append(bot)
    return "\n".join(lines)

def interactive_menu(default_target=None):
    """Show the menu and keep prompting until a complete, valid selection is
    made. Returns an options dict ready to drive one analysis run, or None
    if the user chose to quit. Bad input (typo'd mode, empty target, a
    non-numeric PID) just re-prompts instead of killing the whole session."""
    print(f"\n{_menu_box()}")
    valid_modes = {k for k, _ in MENU_ITEMS if k != "q"}

    while True:
        choice = input(f"\n{GREEN}Select mode → {RESET}").strip().lower()
        if choice == "q":
            return None
        if choice not in valid_modes:
            print(f"{RED}[!] Unknown option '{choice}'. Choose 1-7 or q.{RESET}")
            continue

        if choice == "6":
            target = input(f"{GREEN}PID → {RESET}").strip()
        elif default_target:
            target = input(f"{GREEN}Target binary [{default_target}] → {RESET}").strip() or default_target
        else:
            target = input(f"{GREEN}Target binary → {RESET}").strip()

        if not target:
            print(f"{RED}[!] No target supplied.{RESET}")
            continue

        opts = {"binary": None, "proc": None, "runtime": False,
                "trace": False, "deep": False, "json": None}

        if choice == "6":
            try:
                opts["proc"] = int(target)
            except ValueError:
                print(f"{RED}[!] PID must be numeric.{RESET}")
                continue
            opts["deep"] = True
        else:
            opts["binary"] = target

        if choice == "2":
            opts["runtime"] = True
        elif choice == "3":
            opts["runtime"] = opts["deep"] = True
        elif choice == "4":
            opts["trace"] = True
        elif choice == "5":
            opts["runtime"] = opts["deep"] = opts["trace"] = True
        elif choice == "7":
            opts["runtime"] = opts["deep"] = opts["trace"] = True
            opts["json"] = input(
                f"{GREEN}JSON filename [processscope_report.json] → {RESET}"
            ).strip() or "processscope_report.json"

        return opts

def run_once(args):
    """Execute exactly one analysis pass for an already-populated set of
    options (either parsed CLI args or an interactive_menu() result)."""
    report = {"version": VERSION, "timestamp": time.time()}

    if args.proc is not None:
        report["runtime"] = proc_report(args.proc, args.deep)
        kernel_internals(None, "")
        if args.json:
            save_json(args.json, report)
        return report

    path = Path(args.binary).expanduser().resolve()
    if not path.exists():
        print(f"{RED}[!] Target not found: {path}{RESET}")
        return report

    print(f"\n  {WHITE}TARGET{RESET}  {path}")

    # Static analysis is always the first layer for a binary.
    report["static"] = elf_report(path)

    if getattr(args, "fuzz", False):
        sec("21  AFL++ FUZZING")
        print(f"  Mode: {args.fuzz_mode}  (stdin=file redirected to stdin; file=@@ argument; harness=your purpose-built executable)")
        report["fuzzing"] = fuzzing.launch(path, args.fuzz_mode, args.input_dir, args.output_dir,
                                           args.fuzz_timeout, args.target_arg)
        fuzz_result = report["fuzzing"]
        if fuzz_result.get("ok"):
            row("Workspace", fuzz_result["output"])
            row("Return code", fuzz_result["returncode"])
            row("Crashes", len(fuzz_result["status"]["crashes"]))
            output = (fuzz_result.get("stderr") or fuzz_result.get("stdout") or "").strip()
            if output: print("  AFL++ output (tail):\n" + "\n".join("    " + x for x in output.splitlines()[-12:]))
        else:
            print(f"  {RED}[!] {fuzz_result.get('error')}{RESET}")

    if args.runtime:
        report["runtime"] = runtime_launch(path, args.deep, args.trace)
        security_surface(path, report.get("runtime"))

    if args.trace:
        report["syscalls"] = syscall_trace(path)
        kernel_internals(path, report["syscalls"].get("trace", ""))

    if not args.runtime and not args.trace:
        kernel_internals(path, "")

    attack_surface(report["static"], report.get("runtime"), report.get("syscalls"), report.get("fuzzing"))

    if args.json:
        save_json(args.json, report)

    return report

def main():
    ap = argparse.ArgumentParser(description=f"ProcessScope v{VERSION} — Linux runtime analysis framework")
    ap.add_argument("binary", nargs="?", help="ELF binary to analyze")
    ap.add_argument("--proc", type=int, help="inspect an existing PID")
    ap.add_argument("--runtime", action="store_true", help="launch and snapshot target")
    ap.add_argument("--trace", action="store_true", help="trace syscalls")
    ap.add_argument("--deep", action="store_true", help="deeper /proc and memory details")
    ap.add_argument("--json", metavar="FILE", help="export machine-readable report")
    ap.add_argument("--fuzz", action="store_true", help="run a bounded local AFL++ session")
    ap.add_argument("--fuzz-mode", choices=("stdin", "file", "harness"), default="stdin",
                    help="AFL++ input delivery (default: stdin; harness is an explicit target executable)")
    ap.add_argument("--input", dest="input_dir", default="processscope-fuzz/seeds", help="seed directory for --fuzz")
    ap.add_argument("--output", dest="output_dir", default="processscope-fuzz/output", help="AFL++ workspace for --fuzz/status/crashes")
    ap.add_argument("--fuzz-timeout", type=int, default=60, help="AFL++ session duration in seconds (default: 60)")
    ap.add_argument("--target-arg", action="append", default=[], help="target argument; use @@ once in file mode")
    ap.add_argument("--fuzz-status", action="store_true", help="show AFL++ workspace status")
    ap.add_argument("--crashes", action="store_true", help="list crash inputs in AFL++ workspace")
    ap.add_argument("--reproduce-crash", action="store_true", help="run target with crash input supplied as second positional argument")
    ap.add_argument("--gdb-crash", action="store_true", help="launch GDB with crash input supplied as second positional argument")
    ap.add_argument("--harness-template", metavar="FILE", help="write a minimal AFL++ stdin harness template")
    ap.add_argument("crash_file", nargs="?", help="crash input for --reproduce-crash or --gdb-crash")
    ap.add_argument("--version", action="version", version=f"ProcessScope v{VERSION}")
    args = ap.parse_args()

    print(f"{CYAN}{BANNER}{RESET}")

    # Explicit flags mean "run once and exit" so the tool stays scriptable.
    # No flags (optionally with just a bare target) drops into the
    # interactive menu, which keeps re-prompting until the user quits.
    if args.harness_template:
        made, message = fuzzing.write_harness_template(args.harness_template)
        print(f"{GREEN}[+]{RESET}" if made else f"{RED}[!]{RESET}", message)
        return 0 if made else 1

    # Workspace commands do not require an ELF target beyond the optional
    # positional path used for consistent invocation style.
    if args.fuzz_status or args.crashes:
        data = fuzzing.status(args.output_dir)
        if args.crashes:
            for crash in data["crashes"]:
                print(f"{crash['path']}  size={crash['size']} sha256={crash['sha256'][:16]} metadata={crash['metadata']}")
            if not data["crashes"]: print("No AFL++ crashes found.")
        else:
            print(json.dumps(data, indent=2) if args.json else f"Workspace: {data['workspace']}\nInstances: {len(data['instances'])}\nCrashes: {len(data['crashes'])}")
        if args.json: save_json(args.json, data)
        return 0

    if args.reproduce_crash or args.gdb_crash:
        if not args.binary or not args.crash_file:
            ap.error("--reproduce-crash/--gdb-crash require BINARY and CRASH_FILE")
        if args.gdb_crash:
            gdb = fuzzing.available()["gdb"]
            if not gdb:
                print(f"{RED}[!] gdb is not installed{RESET}"); return 1
            target_command = [str(Path(args.binary).resolve())] + args.target_arg
            crash = str(Path(args.crash_file).resolve())
            if args.fuzz_mode == "file":
                target_command = [crash if x == "@@" else x for x in target_command]
                if crash not in target_command:
                    ap.error("file-mode GDB needs --target-arg @@")
                command = [gdb, "--quiet", "--args"] + target_command
            else:
                # GDB's run command uses a shell-like redirection, while the
                # executable itself is still supplied without a shell.
                command = [gdb, "--quiet", "-ex", "set pagination off", "-ex",
                           f"run < {shlex.quote(crash)}", "-ex", "bt", "--args"] + target_command
            print("Launching GDB:", " ".join(command))
            return subprocess.run(command).returncode
        data = fuzzing.reproduce(args.binary, args.crash_file, args.fuzz_mode, args.target_arg)
        print(json.dumps(data, indent=2))
        return 0 if data.get("ok") else 1

    explicit_flags = (
        args.proc is not None or args.runtime or args.trace or
        args.deep or args.json is not None or args.fuzz
    )

    if explicit_flags:
        if args.proc is None and not args.binary:
            ap.error("provide a binary or --proc PID")
        run_once(args)
        return 0

    default_target = args.binary
    try:
        while True:
            opts = interactive_menu(default_target)
            if opts is None:
                print(f"\n{CYAN}[*] Goodbye.{RESET}")
                return 0

            default_target = opts["binary"] or (
                str(opts["proc"]) if opts["proc"] is not None else default_target
            )
            run_once(argparse.Namespace(**opts))

            print(f"\n{CYAN}{'─' * _LOGO_WIDTH}{RESET}")
            input(f"{DIM}Press Enter to return to the menu (Ctrl+C to quit)…{RESET}")
            print(f"{CYAN}{BANNER}{RESET}")
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n{CYAN}[*] Interrupted — goodbye.{RESET}")
        return 0

if __name__=="__main__":
    raise SystemExit(main())
