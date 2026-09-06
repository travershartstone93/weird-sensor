#!/bin/bash
# Live test. Needs root: starts the sensor, fires decoy processes, and checks
# that the expected NDJSON lines show up with the right pids.
set -u
cd "$(dirname "$0")/.." || exit 1

if [ "$(id -u)" != 0 ]; then
	echo "live.sh: must run as root (sudo make test-live)"
	exit 1
fi
[ -x ./weird-sensor ] || { echo "live.sh: build weird-sensor first"; exit 1; }

TMP=$(mktemp -d)
OUT=$TMP/events.ndjson
ERR=$TMP/stderr
SPID=
fail=0
skipped=0
trap '[ -n "$SPID" ] && kill "$SPID" 2>/dev/null; rm -rf "$TMP"' EXIT

TRACEFS=/sys/kernel/tracing
[ -d $TRACEFS/events ] || TRACEFS=/sys/kernel/debug/tracing

tp() { [ -d "$TRACEFS/events/$1" ]; }

skip() { echo "skip $1: $2"; skipped=$((skipped + 1)); }

expect() {
	local label=$1 re=$2
	for _ in $(seq 50); do
		if grep -qE "$re" "$OUT"; then
			echo "ok   $label"
			return 0
		fi
		sleep 0.1
	done
	echo "FAIL $label: no line matching $re"
	fail=1
	return 1
}

./weird-sensor >"$OUT" 2>"$ERR" &
SPID=$!
for _ in $(seq 50); do
	grep -q '"kind":"hello"' "$OUT" 2>/dev/null && break
	sleep 0.1
done
if ! kill -0 "$SPID" 2>/dev/null; then
	echo "FAIL sensor exited early:"
	cat "$ERR"
	exit 1
fi
grep -q '"kind":"hello"' "$OUT" || { echo "FAIL no hello within 5s"; cat "$ERR"; exit 1; }

if tp sched/sched_process_exec; then
	cp "$(command -v sleep)" "$TMP/decoy-sleep"
	"$TMP/decoy-sleep" 0.1 &
	DPID=$!
	wait "$DPID"
	expect exec "\"kind\":\"exec\",\"pid\":$DPID,.*\"path\":\"$TMP/decoy-sleep\""
	expect exit "\"kind\":\"exit\",\"pid\":$DPID,"
else
	skip exec "tracepoint sched/sched_process_exec missing"
fi

if tp syscalls/sys_enter_memfd_create; then
	MPID=$(python3 -c 'import os; os.memfd_create("weird-decoy"); print(os.getpid())')
	expect memfd "\"kind\":\"memfd\",\"pid\":$MPID,.*\"name\":\"weird-decoy\""
else
	skip memfd "tracepoint syscalls/sys_enter_memfd_create missing"
fi

if tp syscalls/sys_enter_ptrace; then
	read -r TRACER TRACEE < <(python3 - <<'EOF'
import ctypes, os, signal, time
libc = ctypes.CDLL(None, use_errno=True)
child = os.fork()
if child == 0:
    time.sleep(5)
    os._exit(0)
libc.ptrace(16, child, None, None)
os.waitpid(child, 0)
libc.ptrace(17, child, None, None)
os.kill(child, signal.SIGKILL)
os.waitpid(child, 0)
print(os.getpid(), child)
EOF
)
	expect ptrace "\"kind\":\"ptrace\",\"pid\":$TRACER,.*\"request\":16,\"target\":$TRACEE\}"
else
	skip ptrace "tracepoint syscalls/sys_enter_ptrace missing"
fi

if tp sock/inet_sock_set_state; then
	CPID=$(python3 -c 'import os, socket
s = socket.socket()
s.settimeout(1)
try:
    s.connect(("127.0.0.1", 9))
except OSError:
    pass
print(os.getpid())')
	expect connect "\"kind\":\"connect\",\"pid\":$CPID,.*\"daddr\":\"127.0.0.1\",\"dport\":9\}"
else
	skip connect "tracepoint sock/inet_sock_set_state missing"
fi

if tp syscalls/sys_enter_bpf && command -v bpftool >/dev/null; then
	bpftool prog show >/dev/null 2>&1 &
	BPID=$!
	wait "$BPID"
	expect bpf "\"kind\":\"bpf\",\"pid\":$BPID,"
else
	skip bpf "tracepoint syscalls/sys_enter_bpf or bpftool missing"
fi

skip module "no harmless module load to trigger; checked by hand with modprobe"

if grep -vE '"kind":"(hello|lost)"' "$OUT" | grep -qE "\"(pid|tgid)\":${SPID}[,}]"; then
	echo "FAIL sensor reported its own pid $SPID"
	fail=1
else
	echo "ok   own pid filtered"
fi

if head -n1 "$OUT" | grep -q '"kind":"hello"'; then
	echo "ok   hello first"
else
	echo "FAIL first line is not hello"
	fail=1
fi

if python3 -c 'import json, sys
for line in sys.stdin:
    json.loads(line)' <"$OUT"; then
	echo "ok   every line parses as JSON"
else
	echo "FAIL a line did not parse as JSON"
	fail=1
fi

kill -TERM "$SPID"
wait "$SPID"
rc=$?
SPID=
if [ "$rc" = 0 ]; then
	echo "ok   SIGTERM exit 0"
else
	echo "FAIL exit status $rc after SIGTERM"
	fail=1
fi

if [ "$fail" != 0 ]; then
	echo "--- events ---"
	cat "$OUT"
	echo "--- stderr ---"
	cat "$ERR"
fi
echo "live: $(grep -c '^' "$OUT") events, $skipped check(s) skipped, $([ "$fail" = 0 ] && echo PASS || echo FAIL)"
exit "$fail"
