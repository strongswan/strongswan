#!/bin/bash

# we run an unprinted group, as it seems the first run is inaccurate (cache?)

echo "testing gmp"
# gmp needs a RNG plugin, pick gcrypt
sudo ./dh_speed "gmp gcrypt" 400 modp768 modp768 modp1024 modp1024s160 modp1536 modp2048 modp2048s224 modp2048s256 | tail -n 7
sudo ./dh_speed "gmp gcrypt" 100 modp1024 modp3072 modp4096 | tail -n 2
sudo ./dh_speed "gmp gcrypt" 5 modp2048 modp6144 modp8192 | tail -n 2

echo "testing gcrypt"
sudo ./dh_speed "gcrypt" 400 modp768 modp768 modp1024 modp1024s160 modp1536 modp2048 modp2048s224 modp2048s256 | tail -n 7
sudo ./dh_speed "gcrypt" 100 modp1024 modp3072 modp4096 | tail -n 2
sudo ./dh_speed "gcrypt" 5 modp2048 modp6144 modp8192 | tail -n 2

echo "testing openssl"
sudo ./dh_speed "openssl" 400 modp768 modp768 modp1024 modp1024s160 modp1536 modp2048 modp2048s224 modp2048s256 | tail -n 7
sudo ./dh_speed "openssl" 100 modp1024 modp3072 modp4096 | tail -n 2
sudo ./dh_speed "openssl" 5 modp2048 modp6144 modp8192 | tail -n 2
sudo ./dh_speed "openssl" 300 ecp192 ecp192 ecp224 ecp256 ecp384 ecp521 | tail -n 5

