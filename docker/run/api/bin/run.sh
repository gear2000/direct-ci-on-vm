#!/bin/sh

export THREADS=2
export APP_HOME=/opt/api
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${APP_HOME}/bin:${APP_HOME}/sbin
export caller="api"
cd $APP_HOME/bin
gunicorn -w $THREADS -t 120 -b :8021 --access-logfile - --error-logfile - run:app
