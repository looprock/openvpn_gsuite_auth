#!/bin/bash
if [ -z "$1" ]
  then
    echo "ERROR: One Time Password (OTP) is required"
    exit 1
fi
if [ -z "$VPNPASSWORD" ]
  then
    echo "ERROR: please export your vpn password as VPNPASSWORD to use this script"
    exit 1
fi

if [ -z "$username" ]
  then
    echo "ERROR: please export your vpn username as 'username' to use this script"
    exit 1
fi
OTP=`echo -n $1 | base64`
VPNPASSWD=`echo -n $VPNPASSWORD | base64`
PASSWORD="SCRV1:${VPNPASSWD}:${OTP}"
export password=${PASSWORD}
echo "password: ${password}"
go run gsuite_auth.go
