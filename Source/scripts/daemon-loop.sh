#!/bin/bash

while [ 1 ]
do
	ip x p f
	ip x s f
	rm /var/run/charon.*
	make
	bin/charon
	echo ""
	echo "----------------------------"
	echo ""
done
