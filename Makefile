BPF_CLANG ?= clang
CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra
BPF_CFLAGS ?= -O2 -g -Wall -target bpf

.PHONY: all clean dashboard

all: build/frer_kern.o build/frerctl

build:
	mkdir -p build

build/frer_kern.o: src/frer_kern.c | build
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

build/frerctl: src/frerctl.c | build
	$(CC) $(CFLAGS) $< -o $@ -lbpf -lelf -lz

clean:
	rm -rf build

dashboard:
	python3 dashboard/server.py
