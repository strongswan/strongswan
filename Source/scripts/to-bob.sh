#!/bin/bash

# enable ip forwarding for gateway
echo 1 > /proc/sys/net/ipv4/ip_forward

# add connection to bob
MY_ADDR=192.168.0.1                           # Address of local peer
OTHER_ADDR=192.168.0.2                        # Address of remote peer
MY_ID="C=CH, O=Linux strongSwan, CN=alice"    # ID of local peer
OTHER_ID="C=CH, O=Linux strongSwan, CN=bob"   # ID of remote peer
MY_NET=10.1.0.0                               # protected local subnet
OTHER_NET=10.2.0.0                            # protected remote subnet
MY_BITS=16                                    # size of subnet
OTHER_BITS=16                                 # size of subnet
CONN_NAME=to-bob                              # connection name

bin/stroke add $CONN_NAME "$MY_ID" "$OTHER_ID" $MY_ADDR $OTHER_ADDR $MY_NET $OTHER_NET $MY_BITS $OTHER_BITS

# initiate
i=0
LIMIT=0

while [ "$i" -lt "$LIMIT" ]
do
  bin/stroke up $CONN_NAME
  let "i += 1"
done
