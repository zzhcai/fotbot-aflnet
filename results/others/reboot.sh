#!/bin/bash

pkill -9 service

$WORKDIR/fotbot/service 127.0.0.1 9999 >> $WORKDIR/service.log 2>&1 &
