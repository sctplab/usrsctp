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
./fuzzer_connect_multi_verbose -timeout=30 $1 2>$1.log
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

grep "# SCTP_PACKET" $1.log > $1.pcap-log
text2pcap -n -l 248 -D -t "%H:%M:%S." $1.pcap-log $1.pcapng
rm $1.pcap-log

echo ""
echo "LOG:   $1.log"
echo "PCAP:  $1.pcapng"
echo ""

# Open Wireshark if we have an X session
if [ -z ${DISPLAY+x} ]; then
    echo "\$DISPLAY unset, skipping wireshark"
else
    wireshark $1.pcapng
fi
