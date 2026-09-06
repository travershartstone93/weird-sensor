#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

#define PTRACE_ATTACH 16
#define PTRACE_SEIZE 0x4206
#define PTRACE_POKETEXT 4
#define PTRACE_POKEDATA 5
#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

const volatile unsigned int own_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, unsigned int);
	__type(value, unsigned long long);
} lost SEC(".maps");

static struct weird_event *reserve(unsigned int kind)
{
	unsigned long long id = bpf_get_current_pid_tgid();
	unsigned long long ug = bpf_get_current_uid_gid();
	unsigned int tgid = id >> 32;
	unsigned int zero = 0;
	struct task_struct *task;
	struct weird_event *e;
	unsigned long long *n;

	if (tgid == 0 || tgid == own_tgid)
		return NULL;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		n = bpf_map_lookup_elem(&lost, &zero);
		if (n)
			(*n)++;
		return NULL;
	}

	task = (struct task_struct *)bpf_get_current_task();
	e->ts = bpf_ktime_get_ns();
	e->kind = kind;
	e->pid = (unsigned int)id;
	e->tgid = tgid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (unsigned int)ug;
	e->gid = ug >> 32;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

SEC("tracepoint/sched/sched_process_exec")
int on_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct weird_event *e = reserve(WEIRD_EXEC);
	unsigned long arg_start;
	unsigned int off;

	if (!e)
		return 0;
	/* __data_loc packs the offset in the low 16 bits, length in the high 16. */
	off = ctx->__data_loc_filename & 0xffff;
	bpf_probe_read_kernel_str(e->u.exec.path, sizeof(e->u.exec.path), (char *)ctx + off);
	e->u.exec.start = BPF_CORE_READ(task, start_time);
	arg_start = BPF_CORE_READ(task, mm, arg_start);
	if (bpf_probe_read_user_str(e->u.exec.argv0, sizeof(e->u.exec.argv0), (void *)arg_start) < 0)
		e->u.exec.argv0[0] = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int on_exit(void *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	unsigned long long id = bpf_get_current_pid_tgid();
	struct weird_event *e;

	if ((unsigned int)id != (unsigned int)(id >> 32))
		return 0;
	e = reserve(WEIRD_EXIT);
	if (!e)
		return 0;
	e->u.exit.code = BPF_CORE_READ(task, exit_code);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int on_memfd(struct trace_event_raw_sys_enter *ctx)
{
	struct weird_event *e = reserve(WEIRD_MEMFD);

	if (!e)
		return 0;
	if (bpf_probe_read_user_str(e->u.memfd.name, sizeof(e->u.memfd.name), (void *)ctx->args[0]) < 0)
		e->u.memfd.name[0] = 0;
	e->u.memfd.flags = ctx->args[1];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int on_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	long req = ctx->args[0];
	struct weird_event *e;

	if (req != PTRACE_ATTACH && req != PTRACE_SEIZE &&
	    req != PTRACE_POKETEXT && req != PTRACE_POKEDATA)
		return 0;
	e = reserve(WEIRD_PTRACE);
	if (!e)
		return 0;
	e->u.ptrace.request = req;
	e->u.ptrace.target = ctx->args[1];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/module/module_load")
int on_module_load(struct trace_event_raw_module_load *ctx)
{
	struct weird_event *e = reserve(WEIRD_MODULE);
	unsigned int off;

	if (!e)
		return 0;
	off = ctx->__data_loc_name & 0xffff;
	bpf_probe_read_kernel_str(e->u.module.name, sizeof(e->u.module.name), (char *)ctx + off);
	e->u.module.fd = -1;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int on_finit_module(struct trace_event_raw_sys_enter *ctx)
{
	struct weird_event *e = reserve(WEIRD_MODULE);

	if (!e)
		return 0;
	__builtin_memcpy(e->u.module.name, "finit_module", sizeof("finit_module"));
	e->u.module.fd = ctx->args[0];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int on_bpf(struct trace_event_raw_sys_enter *ctx)
{
	union bpf_attr *attr = (union bpf_attr *)ctx->args[1];
	struct weird_event *e = reserve(WEIRD_BPF);

	if (!e)
		return 0;
	e->u.bpf.cmd = ctx->args[0];
	e->u.bpf.prog_type = 0;
	if (e->u.bpf.cmd == BPF_PROG_LOAD)
		bpf_probe_read_user(&e->u.bpf.prog_type, sizeof(e->u.bpf.prog_type), &attr->prog_type);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int on_connect(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct weird_event *e;

	if (ctx->newstate != TCP_SYN_SENT)
		return 0;
	e = reserve(WEIRD_CONNECT);
	if (!e)
		return 0;
	e->u.connect.family = ctx->family;
	e->u.connect.dport = ctx->dport;
	if (ctx->family == AF_INET6)
		__builtin_memcpy(e->u.connect.daddr, ctx->daddr_v6, 16);
	else
		__builtin_memcpy(e->u.connect.daddr, ctx->daddr, 4);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
