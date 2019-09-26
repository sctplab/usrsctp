#!/bin/sh
set -e

NPROC=1

if [ "$(uname)" = "Linux" ]; then
    NPROC=$(nproc)
    CC=clang-9
elif [ "$(uname)" = "Darwin" ]; then
    NPROC=$(sysctl -n hw.ncpu)
    CC=/usr/local/opt/llvm/bin/clang
elif [ "$(uname)" = "FreeBSD" ]; then
    NPROC=$(sysctl -n hw.ncpu)
    CC=clang90
else
    echo "Error: $(uname) not supported, sorry!"
    exit 1
fi

if ! [ -x "$(command -v $CC)" ]; then
    echo "Error: $CC is not installed!" >&2
    exit 1
fi

echo "OS :" $(uname)
echo "CC :" $CC
echo "NP :" $NPROC

cmake -Dsctp_build_fuzzer=1 -Dsctp_build_programs=0 -Dsctp_invariants=1 -Dsctp_sanitizer_address=1  -DCMAKE_C_COMPILER="$CC" -DCMAKE_BUILD_TYPE=RelWithDebInfo .
make -j"$NPROC"
