#ifndef WEIRD_FORMAT_H
#define WEIRD_FORMAT_H

#include <stddef.h>
#include "event.h"

size_t format_event(const struct weird_event *e, char *buf, size_t cap);

#endif
