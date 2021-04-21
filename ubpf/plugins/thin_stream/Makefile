SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.bpf)
ifndef NUM_PACKETS_OUT_THRESHOLD
	# as for the linux kernel implementation of TCP
	NUM_PACKETS_OUT_THRESHOLD=4
endif
CFLAGS=-I../../../src/include -I../../../contrib/examples/example_app -I../../../contrib/ -I../../../contrib/ports/unix/port/include -I../.. -DNUM_PACKETS_OUT_THRESHOLD=$(NUM_PACKETS_OUT_THRESHOLD)

all: $(SRC) $(OBJ)

$(OBJ): %.bpf

%.bpf: %.c
	clang-7 $(CFLAGS) -O2 -fno-gnu-inline-asm -emit-llvm -c $< -o - | llc-7 -march=bpf -filetype=obj -o $@

clean:
	rm -rf *.bpf

.PHONY: %.bpf
