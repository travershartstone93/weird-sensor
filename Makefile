CC ?= cc
CLANG ?= clang
BPFTOOL ?= bpftool
LLVM_STRIP ?= llvm-strip
CFLAGS ?= -O2 -g -Wall -Wextra
BPF_CFLAGS ?= -O2 -g -Wall -Wno-missing-declarations
LDLIBS = -lbpf -lelf -lz

BTF ?= /sys/kernel/btf/vmlinux
USER_SRC = src/sensor.c src/json.c src/format.c

all: weird-sensor

vmlinux.h:
	$(BPFTOOL) btf dump file $(BTF) format c > $@

src/sensor.bpf.o: src/sensor.bpf.c src/event.h vmlinux.h
	$(CLANG) -target bpf $(BPF_CFLAGS) -I. -Isrc -c $< -o $@
	-$(LLVM_STRIP) -g $@

src/sensor.skel.h: src/sensor.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

weird-sensor: $(USER_SRC) src/sensor.skel.h src/event.h src/json.h src/format.h
	$(CC) $(CFLAGS) -Isrc $(USER_SRC) -o $@ $(LDLIBS)

static: $(USER_SRC) src/sensor.skel.h
	$(CC) $(CFLAGS) -static -Isrc $(USER_SRC) -o weird-sensor-static $(LDLIBS) -lzstd \
		|| echo "static link failed: needs libbpf.a, libelf.a, libz.a and libzstd.a; the dynamic build still works"

tests/test_json: tests/test_json.c src/json.c src/format.c src/json.h src/format.h src/event.h
	$(CC) $(CFLAGS) -Isrc tests/test_json.c src/json.c src/format.c -o $@

test: tests/test_json
	./tests/test_json

test-live: weird-sensor
	./tests/live.sh

clean:
	rm -f vmlinux.h src/sensor.bpf.o src/sensor.skel.h weird-sensor weird-sensor-static tests/test_json

.PHONY: all static test test-live clean
