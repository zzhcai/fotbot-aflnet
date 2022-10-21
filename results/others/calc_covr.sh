#!/bin/bash

cd $WORKDIR/fotbot

rm -f fotbot.gcda fotbot.gcno

make clean all > /dev/null 2>&1

for file in $1/*
do
	echo 'Running' $(basename $file)
	{
	pkill -9 service
	./service 127.0.0.1 9999 &
	./fotbot-gcov 127.0.0.1 8888 127.0.0.1 9999 &
	aflnet-replay $file FOTBOT 8888
	} > /dev/null 2>&1
done
