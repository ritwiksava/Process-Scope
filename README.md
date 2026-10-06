# ProcessScope

ProcessScope is a local Linux binary and process research toolkit. It combines ELF reconnaissance, `/proc` runtime inspection, optional `strace` behavior summaries, and AFL++ workspace/crash workflow helpers. Findings are observations and research leads, not exploitability claims.

## Install

Ubuntu/WSL needs Python 3 and standard binutils:

```bash
sudo apt install python3 binutils file strace gdb afl++
```

`strace`, `gdb`, and AFL++ are optional. The corresponding commands explain what is unavailable instead of failing the rest of the tool.

## Architecture

- `tools/ProcScope.py` — CLI, ELF recon, runtime `/proc` analysis, tracing and summary.
- `tools/fuzzing.py` — isolated AFL++ workspace, crash, reproduction and harness helpers.
- `examples/` — deliberately minimal AFL++ harness workflow.

## Commands

```bash
# Interactive console or static ELF reconnaissance
python3 tools/ProcScope.py /bin/ls
python3 tools/ProcScope.py --json report.json /bin/ls

# Snapshot a launched program, or inspect a live PID
python3 tools/ProcScope.py --runtime --deep /bin/cat
python3 tools/ProcScope.py --proc 1234 --deep

# Trace file/process/memory/network related system calls and summarize them
python3 tools/ProcScope.py --trace /bin/echo

# AFL++ stdin fuzzing (only appropriate when stdin is a real input surface)
python3 tools/ProcScope.py --fuzz --input seeds --output findings --fuzz-timeout 60 ./target

# File fuzzing: `@@` is required and becomes the current generated input
python3 tools/ProcScope.py --fuzz --fuzz-mode file --target-arg @@ ./target

# Purpose-built harness fuzzing and starter template
python3 tools/ProcScope.py --harness-template examples/target_harness.c
python3 tools/ProcScope.py --fuzz --fuzz-mode harness ./target_harness

# Review results and locally validate a selected input
python3 tools/ProcScope.py --fuzz-status --output findings
python3 tools/ProcScope.py --crashes --output findings
python3 tools/ProcScope.py --reproduce-crash ./target findings/processscope/crashes/id:000000,...
python3 tools/ProcScope.py --gdb-crash ./target findings/processscope/crashes/id:000000,...
```

For file-mode reproduction/GDB, repeat `--fuzz-mode file --target-arg @@`. Use `--target-arg VALUE` repeatedly for target command-line arguments.

## Output and JSON

ELF recon includes class, architecture, endianness, entry point, program and important sections, interpreter, dependencies, imports/exports, PLT/GOT, RPATH/RUNPATH, executable segments, and PIE/NX/RELRO/canary/FORTIFY state. Runtime inspection reports process metadata, maps, stack/heap/WX regions, loaded libraries, safe environment key names, FDs, namespaces and selected kernel state. `--json FILE` emits the structured report for normal analysis, fuzzing, and workspace-status invocations.

## Limitations

ProcessScope does not infer a correct fuzzing grammar or harness from an ELF. Use stdin only for stdin-aware targets, file mode only when the target accepts a path, and harness mode for library/parser APIs. AFL++ normally needs an instrumented target; non-instrumented/QEMU setups require AFL++ configuration outside this tool. Runtime snapshots can miss programs that exit immediately. `strace` may be blocked by container/WSL ptrace policy. Never analyze binaries or inputs without authorization.
