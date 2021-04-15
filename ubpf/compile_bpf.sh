#!/bin/bash

clang-7 -O2 -fno-gnu-inline-asm -I../src/include -I../contrib/examples/example_app -I../contrib/ -I../contrib/ports/unix/port/include -emit-llvm -c $1.c -o - | llc-7 -march=bpf -filetype=obj -o $1.bpf

#include the 4 folders included for example_app
