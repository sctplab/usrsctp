#!/usr/bin/env bash

#
# usage: check-input.sh input_data
#

set -e
set -u

#make

echo "Fuzzer Input: $1"
echo "########## Beginning Fuzzer Chain"
echo ""

set +e
./fuzzer_connect_multi_verbose -timeout=30 $1 2>fuzzer.log
FUZZER_RETVAL=$?
set -e

if [ "$FUZZER_RETVAL" -eq "0" ]; then
        echo "Execution successful - fuzzer terminated without an issue"
elif [ "$FUZZER_RETVAL" -eq "77" ]; then
        echo "Exceution successful - found an issue!"
else
        echo "Internal error, exiting!"
        exit
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
