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

# Find and then delete all files under current directory (.) that:
#  1. contains "cmake" (case-&insensitive) in its path (wholename)
#  2. name is not CMakeLists.txt
find . -iwholename '*cmake*' -not -name CMakeLists.txt -delete

cmake -Dsctp_build_fuzzer=1 -Dsctp_build_programs=0 -Dsctp_invariants=1 -Dsctp_sanitizer_address=1  -DCMAKE_C_COMPILER="$CC" -DCMAKE_BUILD_TYPE=RelWithDebInfo .
#cmake -Dsctp_build_fuzzer=1 -Dsctp_build_programs=0 -Dsctp_invariants=1 -Dsctp_sanitizer_memory=1  -DCMAKE_C_COMPILER="$CC" -DCMAKE_BUILD_TYPE=RelWithDebInfo .
make -j"$NPROC"
