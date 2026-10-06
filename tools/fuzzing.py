"""AFL++ integration used by ProcessScope.

This module deliberately only orchestrates local AFL++ runs.  It does not
claim that a binary has a useful fuzz target: callers choose stdin, file, or
an already-built harness mode explicitly.
"""

import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path


def available():
    """Return paths for optional fuzzing/debugging tools."""
    return {name: shutil.which(name) for name in ("afl-fuzz", "afl-cc", "gdb")}


def _crash_root(output):
    root = Path(output)
    # AFL++ normally places data in <out>/<instance>/crashes.  Also accept a
    # user-provided instance directory to make old workspaces convenient.
    candidates = [root / "processscope" / "crashes", root / "default" / "crashes", root / "crashes"]
    return [p for p in candidates if p.is_dir()]


def list_crashes(output):
    crashes = []
    for crash_dir in _crash_root(output):
        for item in sorted(crash_dir.iterdir()):
            if not item.is_file() or item.name == "README.txt":
                continue
            raw = item.read_bytes()
            stat = item.stat()
            crashes.append({
                "path": str(item.resolve()), "name": item.name,
                "size": stat.st_size, "mtime": stat.st_mtime,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "metadata": parse_crash_name(item.name),
            })
    return sorted(crashes, key=lambda x: x["mtime"])


def parse_crash_name(name):
    """Extract AFL++ filename fields without relying on one exact version."""
    result = {}
    for field in name.split(","):
        if ":" in field:
            key, value = field.split(":", 1)
            result[key] = value
    return result


def status(output):
    root = Path(output)
    records = []
    for stats in list(root.glob("*/fuzzer_stats")) + ([root / "fuzzer_stats"] if (root / "fuzzer_stats").is_file() else []):
        values = {}
        for line in stats.read_text(errors="replace").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                values[key.strip()] = value.strip()
        records.append({"instance": stats.parent.name, "stats": values})
    return {"workspace": str(root.resolve()), "instances": records, "crashes": list_crashes(root)}


def ensure_workspace(input_dir, output_dir):
    seeds = Path(input_dir).expanduser().resolve()
    output = Path(output_dir).expanduser().resolve()
    seeds.mkdir(parents=True, exist_ok=True)
    if not any(p.is_file() for p in seeds.iterdir()):
        (seeds / "seed-empty").write_bytes(b"\n")
    output.mkdir(parents=True, exist_ok=True)
    return seeds, output


def launch(target, mode, input_dir, output_dir, timeout=60, target_args=None):
    """Run AFL++ for a bounded local session and return its captured output."""
    tools = available()
    if not tools["afl-fuzz"]:
        return {"ok": False, "error": "afl-fuzz is not installed; install afl++ to enable fuzzing.", "tools": tools}

    target = Path(target).expanduser().resolve()
    if not target.is_file():
        return {"ok": False, "error": f"target not found: {target}", "tools": tools}
    if not target.stat().st_mode & 0o111:
        return {"ok": False, "error": f"target is not executable: {target}", "tools": tools}
    if mode not in {"stdin", "file", "harness"}:
        return {"ok": False, "error": f"unsupported fuzz mode: {mode}", "tools": tools}

    seeds, output = ensure_workspace(input_dir, output_dir)
    extra = list(target_args or [])
    # AFL++ uses -i - to resume an existing instance safely.  A fresh empty
    # output directory still receives the normal seed directory.
    resume = (output / "processscope").exists()
    afl_input = "-" if resume else str(seeds)
    command = [tools["afl-fuzz"], "-M", "processscope", "-i", afl_input, "-o", str(output), "-V", str(timeout), "--", str(target)]
    if mode == "file":
        command += extra or ["@@"]
        if "@@" not in command:
            return {"ok": False, "error": "file mode needs @@ in --target-arg (AFL++ input placeholder).", "tools": tools}
    else:
        command += extra

    started = time.time()
    try:
        result = subprocess.run(command, text=True, capture_output=True, errors="replace", timeout=timeout + 20)
        return {"ok": True, "command": command, "returncode": result.returncode,
                "stdout": result.stdout[-12000:], "stderr": result.stderr[-12000:],
                "duration": time.time() - started, "mode": mode, "input": str(seeds),
                "output": str(output), "tools": tools, "status": status(output)}
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "error": "AFL++ did not exit after its requested time limit.",
                "stdout": (exc.stdout or "")[-12000:], "stderr": (exc.stderr or "")[-12000:],
                "command": command, "tools": tools, "status": status(output)}
    except OSError as exc:
        return {"ok": False, "error": str(exc), "tools": tools}


def reproduce(target, crash, mode="stdin", target_args=None, timeout=10):
    target, crash = Path(target).resolve(), Path(crash).resolve()
    if not target.is_file() or not crash.is_file():
        return {"ok": False, "error": "target or crash input does not exist"}
    command = [str(target)] + list(target_args or [])
    if mode == "file":
        command = [str(crash) if x == "@@" else x for x in command]
        if str(crash) not in command:
            return {"ok": False, "error": "file mode reproduction needs --target-arg @@"}
        stdin = None
    else:
        stdin = crash.read_bytes()
    try:
        result = subprocess.run(command, input=stdin, capture_output=True, timeout=timeout)
        return {"ok": True, "command": command, "returncode": result.returncode,
                "signal": -result.returncode if result.returncode < 0 else None,
                "stdout": result.stdout.decode(errors="replace")[-8000:],
                "stderr": result.stderr.decode(errors="replace")[-8000:]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"target did not finish within {timeout}s", "command": command}
    except OSError as exc:
        return {"ok": False, "error": str(exc), "command": command}


HARNESS_TEMPLATE = r'''/* ProcessScope AFL++ harness template (stdin mode).
 * Build: afl-cc -g -O1 -fsanitize=address -o target_harness target_harness.c
 * Replace exercise_input() with the parser/library API under test. */
#include <stdio.h>
#include <stdlib.h>

static void exercise_input(const unsigned char *data, size_t size) {
    (void)data; (void)size; /* TODO: call your target parser here */
}

int main(void) {
    unsigned char *buf = NULL;
    size_t size = 0, cap = 4096;
    int c;
    buf = malloc(cap);
    if (!buf) return 1;
    while ((c = getchar()) != EOF) {
        if (size == cap) { cap *= 2; buf = realloc(buf, cap); if (!buf) return 1; }
        buf[size++] = (unsigned char)c;
    }
    exercise_input(buf, size);
    free(buf);
    return 0;
}
'''


def write_harness_template(path):
    path = Path(path).expanduser()
    if path.exists():
        return False, f"refusing to overwrite existing file: {path}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(HARNESS_TEMPLATE)
    return True, str(path.resolve())
