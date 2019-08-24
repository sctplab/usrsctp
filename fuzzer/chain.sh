#!/bin/bash

#set -e

make
echo "starte"
#./fuzzer_connected CORPUS_CONNECTED/tsctp-000005 2>fuzzer.log
./fuzzer_connected 2>fuzzer.log
echo "fertig"
text2pcap -n -l 248 -D -t "%H:%M:%S." fuzzer.log fuzzer.pcapng
wireshark fuzzer.pcapng
