#ifndef WEIRD_EVENT_H
#define WEIRD_EVENT_H

#define WEIRD_SCHEMA_V 1
#define WEIRD_VERSION "0.1.0"
#define WEIRD_COMM_LEN 16
#define WEIRD_PATH_LEN 256
#define WEIRD_NAME_LEN 64

enum weird_kind {
	WEIRD_HELLO,
	WEIRD_EXEC,
	WEIRD_EXIT,
	WEIRD_MEMFD,
	WEIRD_PTRACE,
	WEIRD_MODULE,
	WEIRD_BPF,
	WEIRD_CONNECT,
	WEIRD_LOST,
	WEIRD_KINDS
};

struct weird_event {
	unsigned long long ts;
	unsigned int kind;
	unsigned int pid, tgid, ppid, uid, gid;
	char comm[WEIRD_COMM_LEN];
	union {
		struct {
			long long wall, boot;
			char release[WEIRD_NAME_LEN];
			char sensor[16];
		} hello;
		struct {
			unsigned long long start;
			char path[WEIRD_PATH_LEN];
			char argv0[WEIRD_NAME_LEN];
		} exec;
		struct {
			int code;
		} exit;
		struct {
			unsigned int flags;
			char name[WEIRD_NAME_LEN];
		} memfd;
		struct {
			long long request;
			unsigned int target;
		} ptrace;
		struct {
			int fd;
			char name[WEIRD_NAME_LEN];
		} module;
		struct {
			unsigned int cmd, prog_type;
		} bpf;
		struct {
			unsigned short family, dport;
			unsigned char daddr[16];
		} connect;
		struct {
			long long count;
		} lost;
	} u;
};

#endif
