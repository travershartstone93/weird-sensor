#ifndef WEIRD_JSON_H
#define WEIRD_JSON_H

#include <stddef.h>

struct json {
	char *buf;
	size_t cap, len;
	int fields;
	int truncated;
};

void json_begin(struct json *j, char *buf, size_t cap);
void json_str(struct json *j, const char *key, const char *val, size_t max);
void json_int(struct json *j, const char *key, long long val);
size_t json_end(struct json *j);

#endif
