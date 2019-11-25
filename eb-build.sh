#!/bin/sh
aws s3 cp s3://private-conf/apisite/conf.json .
zip -r elb-build.zip *.py requirements.txt .ebextensions conf.json
