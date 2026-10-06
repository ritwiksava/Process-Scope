# ProcessScope examples

Generate a starter stdin harness, implement `exercise_input`, then compile it
with AFL++ instrumentation:

```bash
python3 tools/ProcScope.py --harness-template examples/target_harness.c
afl-cc -g -O1 -fsanitize=address -o examples/target_harness examples/target_harness.c
mkdir -p examples/seeds && printf 'sample\n' > examples/seeds/seed1
python3 tools/ProcScope.py --fuzz --fuzz-mode harness --input examples/seeds --output examples/findings --fuzz-timeout 60 examples/target_harness
```

The template intentionally has no vulnerable parser: it is a place to connect
a library or parser API you are authorized to test.
