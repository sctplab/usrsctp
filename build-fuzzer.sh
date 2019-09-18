#!/bin/sh
set -e

if [[ "$OSTYPE" == "linux-gnu" ]]; then
    echo "OS : LINUX"
    CC=clang-9
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "OS : MAC OS"
    CC=/usr/local/opt/llvm/bin/clang
elif [[ "$OSTYPE" == "freebsd"* ]]; then
    echo "OS : FREEBSD"
    CC=/clang-devel
else
    echo "UNSUPPORTED OS - EXIT"
    exit 1
fi


echo "CC :" $CC
cmake -Dsctp_build_fuzzer=1 =Dsctp_build_programs=0 -Dsctp_invariants=1 -Dsctp_sanitizer_address=1 .