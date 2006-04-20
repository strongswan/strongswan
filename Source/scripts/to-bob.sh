#!/bin/bash

# enable ip forwarding for gateway
echo 1 > /proc/sys/net/ipv4/ip_forward

# add connection to bob
MY_ADDR=192.168.0.1      # Address of local peer, also used as ID
OTHER_ADDR=192.168.0.2   # Address of remote peer, also used as ID
MY_CERT=alice.der        # own certificate
OTHER_CERT=bob.der       # certificate for remote peer
MY_NET=10.1.0.0          # protected local subnet
OTHER_NET=10.2.0.0       # protected remote subnet
MY_BITS=16               # size of subnet
OTHER_BITS=16            # size of subnet
CONN_NAME=to-bob         # connection name

bin/stroke add $CONN_NAME $MY_ADDR $OTHER_ADDR $MY_CERT $OTHER_CERT \
               $MY_ADDR $OTHER_ADDR $MY_NET $OTHER_NET $MY_BITS $OTHER_BITS
               