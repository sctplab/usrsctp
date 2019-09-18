#!/bin/bash

#set -e

make
echo "starte"
#./fuzzer_connected CORPUS_CONNECTED/tsctp-000005 2>fuzzer.log
#./fuzzer_connect_data_sent CORPUS_CONNECT/data-1.bin 2>fuzzer.log
#./fuzzer_connect_data_received CORPUS_CONNECT/data-1.bin 2>fuzzer.log
./fuzzer_connect_multi -timeout=6 timeout-00b96dd43f1251438bb44daa0a5a24ae4df5bce5 2>fuzzer.log
echo "fertig"
text2pcap -n -l 248 -D -t "%H:%M:%S." fuzzer.log fuzzer.pcapng
wireshark fuzzer.pcapng
