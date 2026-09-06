#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <bpf/libbpf.h>
#include "event.h"
#include "format.h"
#include "sensor.skel.h"

#define MAX_LINKS 16

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static long long now_ns(clockid_t clock)
{
	struct timespec ts;

	clock_gettime(clock, &ts);
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void emit(const struct weird_event *e)
{
	char line[2048];
	size_t n = format_event(e, line, sizeof(line));

	fwrite(line, 1, n, stdout);
}

static void self_event(struct weird_event *e, unsigned int kind)
{
	memset(e, 0, sizeof(*e));
	e->ts = now_ns(CLOCK_MONOTONIC);
	e->kind = kind;
	e->pid = e->tgid = getpid();
	e->ppid = getppid();
	e->uid = getuid();
	e->gid = getgid();
	snprintf(e->comm, sizeof(e->comm), "weird-sensor");
}

static void hello(void)
{
	struct weird_event e;
	struct utsname u;

	self_event(&e, WEIRD_HELLO);
	e.u.hello.wall = time(NULL);
	e.u.hello.boot = e.u.hello.wall - now_ns(CLOCK_BOOTTIME) / 1000000000LL;
	if (uname(&u) == 0)
		memcpy(e.u.hello.release, u.release, sizeof(e.u.hello.release) - 1);
	snprintf(e.u.hello.sensor, sizeof(e.u.hello.sensor), "%s", WEIRD_VERSION);
	emit(&e);
}

static int handle_event(void *ctx, void *data, size_t len)
{
	(void)ctx;
	if (len >= sizeof(struct weird_event))
		emit(data);
	return 0;
}

static long long read_lost(struct sensor_bpf *skel, unsigned long long *vals, int ncpu)
{
	unsigned int zero = 0;
	long long sum = 0;
	int i;

	if (bpf_map__lookup_elem(skel->maps.lost, &zero, sizeof(zero), vals,
				 ncpu * sizeof(*vals), 0))
		return 0;
	for (i = 0; i < ncpu; i++)
		sum += vals[i];
	return sum;
}

static int attach_all(struct sensor_bpf *skel, struct bpf_link **links)
{
	struct bpf_program *prog;
	int n = 0;

	bpf_object__for_each_program(prog, skel->obj) {
		if (!bpf_program__autoload(prog) || n >= MAX_LINKS)
			continue;
		links[n] = bpf_program__attach(prog);
		if (!links[n]) {
			int err = -errno;

			if (err == -ENOENT) {
				fprintf(stderr, "weird-sensor: %s not available on this kernel, skipping\n",
					bpf_program__section_name(prog));
				continue;
			}
			fprintf(stderr, "weird-sensor: attaching %s failed: %s\n",
				bpf_program__section_name(prog), strerror(-err));
			return err;
		}
		n++;
	}
	return 0;
}

static void usage(FILE *out)
{
	fprintf(out, "usage: weird-sensor [--hello] [--version] [--no-connect]\n");
}

static int debug_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
	(void)level;
	return vfprintf(stderr, fmt, args);
}

int main(int argc, char **argv)
{
	struct bpf_link *links[MAX_LINKS] = { 0 };
	struct sensor_bpf *skel;
	struct ring_buffer *rb;
	struct sigaction sa = { .sa_handler = on_signal };
	unsigned long long *lost_vals;
	long long lost_seen = 0;
	time_t last_check = 0;
	int no_connect = 0, ncpu, err = 0, i;

	setvbuf(stdout, NULL, _IOLBF, 0);
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--hello")) {
			hello();
			return 0;
		} else if (!strcmp(argv[i], "--version")) {
			printf("weird-sensor %s (schema v%d)\n", WEIRD_VERSION, WEIRD_SCHEMA_V);
			return 0;
		} else if (!strcmp(argv[i], "--no-connect")) {
			no_connect = 1;
		} else if (!strcmp(argv[i], "--help")) {
			usage(stdout);
			return 0;
		} else {
			usage(stderr);
			return 2;
		}
	}

	if (getenv("WEIRD_SENSOR_DEBUG"))
		libbpf_set_print(debug_print);
	if (geteuid() != 0) {
		fprintf(stderr, "weird-sensor: must run as root (loading BPF programs needs CAP_BPF and CAP_PERFMON)\n");
		return 3;
	}

	skel = sensor_bpf__open();
	if (!skel) {
		fprintf(stderr, "weird-sensor: opening BPF object failed: %s\n", strerror(errno));
		return 3;
	}
	skel->rodata->own_tgid = getpid();
	if (no_connect)
		bpf_program__set_autoload(skel->progs.on_connect, false);

	err = sensor_bpf__load(skel);
	if (err && !no_connect) {
		/* Some kernels reject the socket tracepoint program; keep the rest running. */
		fprintf(stderr, "weird-sensor: kernel rejected on_connect (%s), connect events disabled\n",
			strerror(-err));
		sensor_bpf__destroy(skel);
		skel = sensor_bpf__open();
		if (!skel) {
			fprintf(stderr, "weird-sensor: opening BPF object failed: %s\n", strerror(errno));
			return 3;
		}
		skel->rodata->own_tgid = getpid();
		bpf_program__set_autoload(skel->progs.on_connect, false);
		err = sensor_bpf__load(skel);
	}
	if (err) {
		fprintf(stderr, "weird-sensor: loading BPF programs failed: %s (libbpf messages above)\n",
			strerror(-err));
		sensor_bpf__destroy(skel);
		return 3;
	}
	if (attach_all(skel, links)) {
		sensor_bpf__destroy(skel);
		return 3;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "weird-sensor: ring buffer setup failed: %s\n", strerror(errno));
		sensor_bpf__destroy(skel);
		return 3;
	}
	ncpu = libbpf_num_possible_cpus();
	lost_vals = calloc(ncpu > 0 ? ncpu : 1, sizeof(*lost_vals));

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	hello();

	while (!stop) {
		err = ring_buffer__poll(rb, 250);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "weird-sensor: polling failed: %s\n", strerror(-err));
			break;
		}
		err = 0;
		if (time(NULL) != last_check) {
			long long total = read_lost(skel, lost_vals, ncpu);

			last_check = time(NULL);
			if (total > lost_seen) {
				struct weird_event e;

				self_event(&e, WEIRD_LOST);
				e.u.lost.count = total - lost_seen;
				emit(&e);
				lost_seen = total;
			}
		}
	}

	ring_buffer__free(rb);
	for (i = 0; i < MAX_LINKS; i++)
		bpf_link__destroy(links[i]);
	sensor_bpf__destroy(skel);
	free(lost_vals);
	return err ? 1 : 0;
}
