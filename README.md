# weird-sensor

A small root-only eBPF collector that prints one JSON line per
security-relevant process event: exec, exit, memfd_create, ptrace attach,
module load, bpf() calls and outbound TCP connects. It exists so that
[weird](https://github.com/travershartstone93/weird) can score a process the
moment it starts instead of finding it later in /proc.

The whole thing is about 600 lines of C. It has no network code, no config
file and reads no untrusted input. It writes NDJSON to stdout and that is all.

## Output

Every line is one JSON object. Common fields:

| field | meaning |
|-------|---------|
| `v`    | schema version, currently 1 |
| `ts`   | monotonic nanoseconds (`bpf_ktime_get_ns`), see the hello event to convert |
| `kind` | `hello`, `exec`, `exit`, `memfd`, `ptrace`, `module`, `bpf`, `connect`, `lost` |
| `pid`, `tgid`, `ppid`, `uid`, `gid` | the task that caused the event |
| `comm` | 16-byte task name |

Per kind:

| kind | extra fields |
|------|--------------|
| `hello`   | `wall` (epoch seconds when `ts` was taken), `boot` (boot time, epoch seconds), `release` (uname), `sensor` (version) |
| `exec`    | `path` (filename passed to execve, up to 256 bytes), `argv0`, `start` (task start_time ns, for a (pid, start) key) |
| `exit`    | `code` (exit status), `signal` (only when killed by a signal); one per process, not per thread |
| `memfd`   | `name`, `flags` |
| `ptrace`  | `request` (raw; only ATTACH 16, SEIZE 16902, POKETEXT 4, POKEDATA 5 are reported), `target` pid |
| `module`  | `name` from the module_load tracepoint, or `name` = `finit_module` plus `fd` when only the syscall was seen |
| `bpf`     | `cmd` (5 is BPF_PROG_LOAD), `prog_type` when cmd is 5 |
| `connect` | `family` (2 or 10), `daddr` as text, `dport` |
| `lost`    | `count` of events dropped because the ring buffer was full; a consumer should rescan |

To turn `ts` into wall clock time: `wall_of(ts) = hello.wall + (ts - hello.ts) / 1e9`.

Example:

```
{"v":1,"ts":48291837261,"kind":"hello","pid":4120,"tgid":4120,"ppid":4119,"uid":0,"gid":0,"comm":"weird-sensor","wall":1788480000,"boot":1788431709,"release":"7.2.2-1-cachyos","sensor":"0.1.0"}
{"v":1,"ts":48292001923,"kind":"exec","pid":4131,"tgid":4131,"ppid":4130,"uid":1000,"gid":1000,"comm":"sleep","path":"/tmp/x/decoy-sleep","argv0":"/tmp/x/decoy-sleep","start":48291998811}
{"v":1,"ts":48292412345,"kind":"memfd","pid":4133,"tgid":4133,"ppid":4130,"uid":1000,"gid":1000,"comm":"python3","name":"weird-decoy","flags":0}
```

## Hooks

| tracepoint | event |
|------------|-------|
| `sched/sched_process_exec` | exec |
| `sched/sched_process_exit` | exit |
| `syscalls/sys_enter_memfd_create` | memfd |
| `syscalls/sys_enter_ptrace` | ptrace |
| `module/module_load` | module |
| `syscalls/sys_enter_finit_module` | module (fallback view) |
| `syscalls/sys_enter_bpf` | bpf |
| `sock/inet_sock_set_state` (new state SYN_SENT) | connect |

Events for pid 0 and for the sensor's own process are dropped inside the
kernel, so the sensor never reports itself. If a tracepoint does not exist on
the running kernel (for example `module/module_load` with modules disabled)
the sensor prints a warning and carries on without it.

## Build

Needs clang, libbpf (1.0 or later), bpftool, libelf and zlib, plus a kernel
with BTF at `/sys/kernel/btf/vmlinux`. On Arch: `pacman -S clang libbpf bpf`.
On Debian and Ubuntu: `apt install clang llvm libbpf-dev libelf-dev zlib1g-dev
linux-tools-common linux-tools-generic`.

```
make          # vmlinux.h, BPF object, skeleton, userspace binary
make test     # unit tests, no root needed
sudo make test-live   # starts the sensor and fires decoys
make static   # tries a static link, prints a message if the .a files are missing
```

`vmlinux.h` is generated from the running kernel's BTF and is not committed.
Thanks to CO-RE the resulting binary runs on other kernels with BTF too.

## Run

```
sudo ./weird-sensor | head
```

Flags:

- `--hello` prints the hello event and exits 0 without loading anything. Used
  by the systemd unit as a self-check and by weird to probe for the sensor.
- `--version` prints the version and schema.
- `--no-connect` skips the socket hook.

Not root, or a load failure, gives a message on stderr and exit status 3.
SIGINT or SIGTERM ends the sensor cleanly with exit status 0.

## Install as a service

```
sudo install -m 0755 weird-sensor /usr/local/bin/weird-sensor
sudo install -m 0644 systemd/weird-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now weird-sensor
tail -f /run/weird/events.ndjson
```

The unit appends to `/run/weird/events.ndjson`, world readable, so an
unprivileged consumer can tail it.

## Security posture

- Runs as root because loading BPF programs needs it
  (`unprivileged_bpf_disabled=2` is the expected setting), but under a tight
  systemd sandbox: capability bounding set of CAP_BPF, CAP_PERFMON and
  CAP_SYS_RESOURCE, `ProtectSystem=strict`, `ProtectHome=yes`,
  `PrivateNetwork=yes`, `NoNewPrivileges=yes`, and the rest of the usual
  hardening knobs. The unit file has a comment about the extra capability
  older kernels want.
- Output only. It never reads a file it did not create, never opens a socket,
  and takes no input beyond three command line flags.
- Every string that came from the kernel or from user memory is escaped
  before it is printed: quotes, backslashes, control characters and bytes
  that are not valid UTF-8 come out as `\uXXXX`. A hostile process name or
  path cannot break the line format.
- The JSON writer works in a fixed buffer and truncates with `...` rather
  than overflow. `tests/test_json.c` covers this.
- The BPF side only reads. It never writes to task memory and never blocks
  an action. Enforcement would be a BPF LSM program and a different risk
  profile; that is deliberately out of scope.
- The user space side does one thing per event: format and write.

## Why not a kernel module

A kernel module runs with no safety net: a bug in it is a kernel bug, and on
a machine with Secure Boot, lockdown and module signing it will not load at
all unless you sign it and manage the keys. An eBPF program is checked by
the kernel's verifier before it runs, cannot loop forever, cannot touch
memory it was not given, and unloads the moment the process that loaded it
exits. It also works under lockdown. That makes it the right tool for a
sensor that is supposed to be small, reviewable and boring.

## Tests

- `make test` builds and runs `tests/test_json`: escaping, truncation, and
  one well formed line for every event kind.
- `sudo make test-live` runs `tests/live.sh`: starts the sensor writing to a
  temp file, runs decoys (a copied `sleep` for exec and exit, Python
  `os.memfd_create`, a ctypes `PTRACE_ATTACH` on a child, a TCP connect to
  127.0.0.1:9, `bpftool prog show` for bpf), then checks that each expected
  line is present with the right pid, that the sensor's own pid never shows
  up, that every line parses as JSON, that hello comes first, and that
  SIGTERM gives exit status 0. Checks whose tracepoint is missing on the
  running kernel are skipped with a message. Module load is not exercised
  because there is no harmless way to do it on every machine.
- CI runs all of the above on ubuntu-latest, including the live test under
  sudo.

## License

MIT, see LICENSE.
