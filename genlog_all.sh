#!/bin/bash

for i in {16..6}
do
    LEN=$(echo "2 ^ $i" | bc)
    echo "Generating output logs for input length ${LEN} bytes."
    command time -v --output=./logs/time_output_${LEN}.txt ./target/release/examples/sha256 $i > ./logs/output_${LEN}.txt
    if [ $i -ne 6 ]; then
        if [ $i -gt 10 ]; then
            echo "Sleeping for 60 seconds to give the CPU a break"
            sleep 60s
        else
            echo "Sleeping for 30 seconds to give the CPU a break"
            sleep 30s
        fi
    fi
done
echo "See logs directory for output files"
