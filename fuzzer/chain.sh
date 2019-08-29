#!/bin/bash

#set -e

make
echo "starte"
#./fuzzer_connected CORPUS_CONNECTED/tsctp-000005 2>fuzzer.log
./fuzzer_connect_established CORPUS_CONNECT/data-1.bin 2>fuzzer.log
echo "fertig"
text2pcap -n -l 248 -D -t "%H:%M:%S." fuzzer.log fuzzer.pcapng
wireshark fuzzer.pcapng
