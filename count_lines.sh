#!/bin/bash

if [ $# -lt 1 ]
then
	echo "Usage: $0 file ..."
	exit 1
fi

lines=0
files=0
sum_lines=0

for f in $*
do
	# l=`wc -l $f | cut -f1 -d ' '`
	lines=`wc -l < $f`
	echo "$f: $lines"
	files=$(($files + 1))
	sum_lines=$(($sum_lines + $lines))
done

echo "$files files in total, with $sum_lines lines in total."

