#!/usr/bin/env bash
# example script to purge the blacklisting host list using the REST API
source ./common.sh
echo Retrieving blacklisting host list...
CURL_OUTPUT=`curl $CURL_OPTIONS $DF_SERVER_BASE_URL/modules/api/spamfiltering/v1/blacklisting/hosts`
echo "Blacklisted hosts:"
echo $CURL_OUTPUT
