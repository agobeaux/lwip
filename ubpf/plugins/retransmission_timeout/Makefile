SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.bpf)
ifndef RTO_MAX_VALUE
	RTO_MAX_VALUE=1600
endif
CFLAGS=-I../../../src/include -I../../../contrib/examples/example_app -I../../../contrib/ -I../../../contrib/ports/unix/port/include -I../.. -DRTO_MAX_VALUE=$(RTO_MAX_VALUE)

all: $(SRC) $(OBJ)

$(OBJ): %.bpf

%.bpf: %.c
	clang-7 $(CFLAGS) -O2 -fno-gnu-inline-asm -emit-llvm -c $< -o - | llc-7 -march=bpf -filetype=obj -o $@

clean:
	rm -rf *.bpf

.PHONY: %.bpf
