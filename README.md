# phax

A command-line "Cheat Engine" clone for Linux, implemented using ptrace.

## Usage

Run the "hackme" program:
```
gcc hackme.c -o hackme
./hackme
```

Run the phax wrapper script:
```
./run.sh `pidof hackme` i32
```

## How does it work?

It attaches to the target process using the `ptrace` API, parses
`/proc/<pid>/maps` to determine valid memory regions, then scans
through those regions by reading `/proc/<pid>/mem`. Modifying values
is done by writing to the same file.

## Why doesn't it work on floating point numbers?

Short answer: because I'm lazy.

Long answer: because floating point numbers have a lot of precision,
and unless you know the exact value, you typically need a range of
values rather than a single value. Searching for a range with acceptable
performance is much more complex than searching for a single value, so
it is not implemented at this time.
