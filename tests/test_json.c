#include <stdio.h>
#include <string.h>
#include "event.h"
#include "format.h"
#include "json.h"

static int failures;

#define CHECK(cond) do { \
	if (!(cond)) { \
		failures++; \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
	} \
} while (0)

static void one_str(char *out, size_t cap, const char *val, size_t max)
{
	struct json j;

	json_begin(&j, out, cap);
	json_str(&j, "s", val, max);
	json_end(&j);
}

static void test_escaping(void)
{
	char out[256];

	one_str(out, sizeof(out), "a\"b\\c\n\t\r\x01\x1f", 64);
	CHECK(!strcmp(out, "{\"s\":\"a\\\"b\\\\c\\n\\t\\r\\u0001\\u001f\"}\n"));

	one_str(out, sizeof(out), "caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80", 64);
	CHECK(!strcmp(out, "{\"s\":\"caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80\"}\n"));

	one_str(out, sizeof(out), "\xff", 64);
	CHECK(!strcmp(out, "{\"s\":\"\\u00ff\"}\n"));
	one_str(out, sizeof(out), "\x80", 64);
	CHECK(!strcmp(out, "{\"s\":\"\\u0080\"}\n"));
	one_str(out, sizeof(out), "\xc0\x80", 64);
	CHECK(!strcmp(out, "{\"s\":\"\\u00c0\\u0080\"}\n"));
	one_str(out, sizeof(out), "\xe2\x82", 64);
	CHECK(!strcmp(out, "{\"s\":\"\\u00e2\\u0082\"}\n"));
	one_str(out, sizeof(out), "\xed\xa0\x80", 64);
	CHECK(!strcmp(out, "{\"s\":\"\\u00ed\\u00a0\\u0080\"}\n"));

	one_str(out, sizeof(out), "abcdefgh", 3);
	CHECK(!strcmp(out, "{\"s\":\"abc\"}\n"));
}

static void test_truncation(void)
{
	char out[40];
	struct json j;
	size_t n;

	memset(out, 'X', sizeof(out));
	json_begin(&j, out, 32);
	json_str(&j, "s", "0123456789012345678901234567890123456789", 64);
	json_int(&j, "n", 12345678);
	n = json_end(&j);
	CHECK(j.truncated);
	CHECK(n < 32);
	CHECK(out[n] == 0);
	CHECK(out[32] == 'X');
	CHECK(!strcmp(out + n - 6, "...\"}\n"));
	CHECK(!strstr(out, "\"n\""));

	json_begin(&j, out, 8);
	json_int(&j, "toolong", 1);
	n = json_end(&j);
	CHECK(!strcmp(out, "{}\n"));
	CHECK(j.truncated);
}

static void test_ints(void)
{
	char out[64];
	struct json j;

	json_begin(&j, out, sizeof(out));
	json_int(&j, "a", -5);
	json_int(&j, "b", 9223372036854775807LL);
	json_end(&j);
	CHECK(!strcmp(out, "{\"a\":-5,\"b\":9223372036854775807}\n"));
}

static void test_every_kind(void)
{
	static const char *const names[WEIRD_KINDS] = {
		"hello", "exec", "exit", "memfd", "ptrace", "module", "bpf", "connect", "lost",
	};
	struct weird_event e;
	char out[2048], want[64];
	unsigned int k;

	for (k = 0; k < WEIRD_KINDS; k++) {
		size_t n;

		memset(&e, 0, sizeof(e));
		e.kind = k;
		e.ts = 123456789012ULL;
		e.pid = 42;
		memcpy(e.comm, "bad\xffname\"\n", 10);
		memset(e.u.exec.path, 'p', sizeof(e.u.exec.path));
		n = format_event(&e, out, sizeof(out));
		CHECK(n == strlen(out));
		CHECK(n > 0 && out[n - 1] == '\n');
		CHECK(strchr(out, '\n') == out + n - 1);
		CHECK(out[0] == '{' && out[n - 2] == '}');
		snprintf(want, sizeof(want), "\"kind\":\"%s\"", names[k]);
		CHECK(strstr(out, want));
		CHECK(strstr(out, "\"v\":1,\"ts\":123456789012,"));
		CHECK(strstr(out, "\"comm\":\"bad\\u00ffname\\\"\\n\""));
	}

	memset(&e, 0, sizeof(e));
	e.kind = WEIRD_CONNECT;
	e.u.connect.family = 2;
	e.u.connect.dport = 9;
	memcpy(e.u.connect.daddr, "\x7f\x00\x00\x01", 4);
	format_event(&e, out, sizeof(out));
	CHECK(strstr(out, "\"family\":2,\"daddr\":\"127.0.0.1\",\"dport\":9}"));

	e.u.connect.family = 10;
	memset(e.u.connect.daddr, 0, 16);
	e.u.connect.daddr[15] = 1;
	format_event(&e, out, sizeof(out));
	CHECK(strstr(out, "\"daddr\":\"::1\""));

	memset(&e, 0, sizeof(e));
	e.kind = WEIRD_EXIT;
	e.u.exit.code = (3 << 8) | 9;
	format_event(&e, out, sizeof(out));
	CHECK(strstr(out, "\"code\":3,\"signal\":9}"));

	memset(&e, 0, sizeof(e));
	e.kind = WEIRD_BPF;
	e.u.bpf.cmd = 5;
	e.u.bpf.prog_type = 2;
	format_event(&e, out, sizeof(out));
	CHECK(strstr(out, "\"cmd\":5,\"prog_type\":2}"));
	e.u.bpf.cmd = 11;
	format_event(&e, out, sizeof(out));
	CHECK(strstr(out, "\"cmd\":11}"));
}

int main(void)
{
	test_escaping();
	test_truncation();
	test_ints();
	test_every_kind();
	if (failures) {
		fprintf(stderr, "%d check(s) failed\n", failures);
		return 1;
	}
	printf("test_json: all checks passed\n");
	return 0;
}
