#!/bin/bash

openssl genrsa -out key.pem 2048
openssl rsa -in key.pem -outform der -out key.der -traditional

openssl req -x509 -nodes -newkey rsa:4096 -keyout cakey.pem -outform der \
	-out ca.der -sha256 -subj "/CN=CA" -addext basicConstraints=critical,CA:TRUE

tkm_cfgtool -c /usr/local/share/tkm/tkm.conf -i swanctl.conf \
	-t tkm.conf -s /usr/local/share/tkm/tkmconfig.xsd
