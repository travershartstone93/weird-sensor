#include <arpa/inet.h>
#include "format.h"
#include "json.h"

static const char *const kind_name[WEIRD_KINDS] = {
	"hello", "exec", "exit", "memfd", "ptrace", "module", "bpf", "connect", "lost",
};

size_t format_event(const struct weird_event *e, char *buf, size_t cap)
{
	char addr[INET6_ADDRSTRLEN];
	struct json j;

	json_begin(&j, buf, cap);
	json_int(&j, "v", WEIRD_SCHEMA_V);
	json_int(&j, "ts", (long long)e->ts);
	json_str(&j, "kind", e->kind < WEIRD_KINDS ? kind_name[e->kind] : "unknown", 16);
	json_int(&j, "pid", e->pid);
	json_int(&j, "tgid", e->tgid);
	json_int(&j, "ppid", e->ppid);
	json_int(&j, "uid", e->uid);
	json_int(&j, "gid", e->gid);
	json_str(&j, "comm", e->comm, sizeof(e->comm));

	switch (e->kind) {
	case WEIRD_HELLO:
		json_int(&j, "wall", e->u.hello.wall);
		json_int(&j, "boot", e->u.hello.boot);
		json_str(&j, "release", e->u.hello.release, sizeof(e->u.hello.release));
		json_str(&j, "sensor", e->u.hello.sensor, sizeof(e->u.hello.sensor));
		break;
	case WEIRD_EXEC:
		json_str(&j, "path", e->u.exec.path, sizeof(e->u.exec.path));
		json_str(&j, "argv0", e->u.exec.argv0, sizeof(e->u.exec.argv0));
		json_int(&j, "start", (long long)e->u.exec.start);
		break;
	case WEIRD_EXIT:
		json_int(&j, "code", (e->u.exit.code >> 8) & 0xff);
		if (e->u.exit.code & 0x7f)
			json_int(&j, "signal", e->u.exit.code & 0x7f);
		break;
	case WEIRD_MEMFD:
		json_str(&j, "name", e->u.memfd.name, sizeof(e->u.memfd.name));
		json_int(&j, "flags", e->u.memfd.flags);
		break;
	case WEIRD_PTRACE:
		json_int(&j, "request", e->u.ptrace.request);
		json_int(&j, "target", e->u.ptrace.target);
		break;
	case WEIRD_MODULE:
		json_str(&j, "name", e->u.module.name, sizeof(e->u.module.name));
		if (e->u.module.fd >= 0)
			json_int(&j, "fd", e->u.module.fd);
		break;
	case WEIRD_BPF:
		json_int(&j, "cmd", e->u.bpf.cmd);
		if (e->u.bpf.cmd == 5)
			json_int(&j, "prog_type", e->u.bpf.prog_type);
		break;
	case WEIRD_CONNECT:
		json_int(&j, "family", e->u.connect.family);
		if (!inet_ntop(e->u.connect.family == 10 ? AF_INET6 : AF_INET,
			       e->u.connect.daddr, addr, sizeof(addr)))
			addr[0] = 0;
		json_str(&j, "daddr", addr, sizeof(addr));
		json_int(&j, "dport", e->u.connect.dport);
		break;
	case WEIRD_LOST:
		json_int(&j, "count", e->u.lost.count);
		break;
	}
	return json_end(&j);
}
