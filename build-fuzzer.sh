#!/bin/sh
set -e

NPROC=1

if [[ "$OSTYPE" == "linux-gnu" ]]; then
    echo "OS : LINUX"
    NPROC=$(nproc)
    CC=clang-9
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "OS : MAC OS"
    NPROC=$(sysctl -n hw.ncpu)
    CC=/usr/local/opt/llvm/bin/clang
elif [[ "$OSTYPE" == "freebsd"* ]]; then
    echo "OS : FREEBSD"
    NPROC=$(sysctl -n hw.ncpu)
    CC=/clang-devel
else
    echo "UNSUPPORTED OS - EXIT"
    exit 1
fi

echo "CC :" $CC
echo "NP :" $NPROC

cmake -Dsctp_build_fuzzer=1 -Dsctp_build_programs=0 -Dsctp_invariants=1 -Dsctp_sanitizer_address=1  -DCMAKE_C_COMPILER="$CC" .
make -j"$NPROC"