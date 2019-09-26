#!/bin/bash

#set -e

make
echo "Beginning..."
#./fuzzer_connected CORPUS_CONNECTED/tsctp-000005 2>fuzzer.log
#./fuzzer_connect_data_sent CORPUS_CONNECT/data-1.bin 2>fuzzer.log
#./fuzzer_connect_data_received CORPUS_CONNECT/data-1.bin 2>fuzzer.log
#./fuzzer_connect_multi -timeout=6 timeout-00b96dd43f1251438bb44daa0a5a24ae4df5bce5 2>fuzzer.log
./fuzzer_connect_multi_verbose -timeout=6 leak-00bd871f5ce0596083fe8642c803c97f424b0c70 2>fuzzer.log
echo "Fuzzing finished"
grep "# SCTP_PACKET" fuzzer.log > text2pcap.log
text2pcap -n -l 248 -D -t "%H:%M:%S." text2pcap.log fuzzer.pcapng
wireshark fuzzer.pcapng
