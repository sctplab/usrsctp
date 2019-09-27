#!/usr/bin/env bash

set -e
set -u

#make

echo "Fuzzer Input: $1"
echo "########## Beginning Fuzzer Chain"
echo ""
#./fuzzer_connected CORPUS_CONNECTED/tsctp-000005 2>fuzzer.log
#./fuzzer_connect_data_sent CORPUS_CONNECT/data-1.bin 2>fuzzer.log
#./fuzzer_connect_data_received CORPUS_CONNECT/data-1.bin 2>fuzzer.log
#./fuzzer_connect_multi -timeout=6 timeout-00b96dd43f1251438bb44daa0a5a24ae4df5bce5 2>fuzzer.log

set +e
./fuzzer_connect_multi_verbose -timeout=30 $1 2>fuzzer.log
FUZZER_RETVAL=$?
set -e

#echo $FUZZER_RETVAL

if [ "$FUZZER_RETVAL" -eq "0" ]; then
        echo "Execution successful - issue not reproducable!"
elif [ "$FUZZER_RETVAL" -eq "77" ]; then
        echo "Exceution successful - found an issue!"
else
        echo "Internal error, exiting!"
        exit;
fi

grep "# SCTP_PACKET" fuzzer.log > text2pcap.log
text2pcap -n -l 248 -D -t "%H:%M:%S." text2pcap.log fuzzer.pcapng

echo ""
echo "LOG:   fuzzer.log"
echo "PCAP:  fuzzer.pcapng"
echo ""

# Open Wireshark if we have an X session
if [ -z ${DISPLAY+x} ]; then
    echo "\$DISPLAY unset, skipping wireshark"
else
    wireshark fuzzer.pcapng
fi
