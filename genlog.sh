#!/bin/bash
if [ $# -eq 0 ]; then
    >&2 echo "No arguments provided. Specify an integer argument n for an input length of 2^n"
    exit 1
fi

LEN=$(echo "2 ^ $1" | bc)
echo $LEN
echo "Generating output logs for input length ${LEN} bytes."
command time -v --output=./logs/time_output_${LEN}.txt ./target/release/examples/sha256 $1 > ./logs/output_${LEN}.txt
echo "See logs directory for output files"
