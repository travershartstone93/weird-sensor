#include <stdio.h>
#include <string.h>
#include "json.h"

/* Bytes always kept free at the end for "}\n" and the terminating NUL. */
#define TAIL 3

static void put(struct json *j, const char *s, size_t n)
{
	memcpy(j->buf + j->len, s, n);
	j->len += n;
}

static size_t room(const struct json *j)
{
	return j->cap - TAIL - j->len;
}

static int key(struct json *j, const char *k, size_t need)
{
	size_t kl = strlen(k);

	if (room(j) < kl + 4 + need) {
		j->truncated = 1;
		return 0;
	}
	put(j, j->fields ? ",\"" : "\"", j->fields ? 2 : 1);
	put(j, k, kl);
	put(j, "\":", 2);
	j->fields++;
	return 1;
}

static size_t utf8_len(const unsigned char *s, size_t n)
{
	unsigned char c = s[0];
	unsigned int cp;
	size_t len, i;

	if (c < 0x80)
		return 1;
	if (c >= 0xc2 && c <= 0xdf) {
		len = 2;
		cp = c & 0x1f;
	} else if (c >= 0xe0 && c <= 0xef) {
		len = 3;
		cp = c & 0x0f;
	} else if (c >= 0xf0 && c <= 0xf4) {
		len = 4;
		cp = c & 0x07;
	} else {
		return 0;
	}
	if (n < len)
		return 0;
	for (i = 1; i < len; i++) {
		if ((s[i] & 0xc0) != 0x80)
			return 0;
		cp = (cp << 6) | (s[i] & 0x3f);
	}
	if ((len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000) ||
	    cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
		return 0;
	return len;
}

void json_begin(struct json *j, char *buf, size_t cap)
{
	j->buf = buf;
	j->cap = cap;
	j->len = 0;
	j->fields = 0;
	j->truncated = 0;
	put(j, "{", 1);
}

void json_str(struct json *j, const char *k, const char *val, size_t max)
{
	const unsigned char *s = (const unsigned char *)val;
	size_t n = strnlen(val, max), i = 0;
	char esc[8];

	if (!key(j, k, 5))
		return;
	put(j, "\"", 1);
	while (i < n) {
		unsigned char c = s[i];
		const char *e = esc;
		size_t el, step = 1;

		if (c == '"' || c == '\\') {
			esc[0] = '\\';
			esc[1] = (char)c;
			el = 2;
		} else if (c == '\n') {
			e = "\\n";
			el = 2;
		} else if (c == '\r') {
			e = "\\r";
			el = 2;
		} else if (c == '\t') {
			e = "\\t";
			el = 2;
		} else if (c >= 0x20 && (el = utf8_len(s + i, n - i)) != 0) {
			e = (const char *)s + i;
			step = el;
		} else {
			snprintf(esc, sizeof(esc), "\\u%04x", c);
			el = 6;
		}
		if (room(j) < el + 4) {
			put(j, "...", 3);
			j->truncated = 1;
			break;
		}
		put(j, e, el);
		i += step;
	}
	put(j, "\"", 1);
}

void json_int(struct json *j, const char *k, long long val)
{
	char num[24];
	size_t n = snprintf(num, sizeof(num), "%lld", val);

	if (key(j, k, n))
		put(j, num, n);
}

size_t json_end(struct json *j)
{
	put(j, "}\n", 2);
	j->buf[j->len] = 0;
	return j->len;
}
