#!/bin/bash

cd $WORKDIR/fotbot

rm -rf $2
mkdir $2

for file in $1/id*
do
	echo 'Running' $(basename $file)
	pkill -9 service
	./service 127.0.0.1 9999 > /dev/null 2>&1 &
	ASAN_OPTIONS=detect_leaks=0 ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer ./fotbot-asan 127.0.0.1 8888 127.0.0.1 9999 > tmp.log 2>&1 &
	pid=$!
	aflnet-replay $file FOTBOT 8888 > /dev/null 2>&1

	wait $pid
	status=$?

	if [ ! $status -eq 0 ]
	then
		cat tmp.log > $2/$(basename $file)
	fi
done

rm -f tmp.log

