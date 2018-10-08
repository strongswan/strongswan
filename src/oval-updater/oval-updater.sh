#!/bin/sh

DIR="/etc/pts"
OVAL_DIR="$DIR/oval"
DATE=`date +%Y%m%d-%H%M`
UBUNTU="https://people.canonical.com/~ubuntu-security/oval"
UBUNTU_VERSIONS="bionic xenial"
DEBIAN="https://www.debian.org/security/oval"
DEBIAN_VERSIONS="stretch jessie wheezy"
CMD=/usr/sbin/oval-updater
CMD_LOG="$DIR/logs/$DATE-oval-update.log"
DEL_LOG=1

mkdir -p $OVAL_DIR
cd $OVAL_DIR

# Download Ubuntu OVAL files

for v in $UBUNTU_VERSIONS
do
  wget -nv $UBUNTU/com.ubuntu.$v.cve.oval.xml -O $v-oval.xml
done

# Download Debian distribution information

for v in $DEBIAN_VERSIONS
do
  wget -nv $DEBIAN/oval-definitions-$v.xml -O $v-oval.xml
done

# Run oval-updater

$CMD --os "Ubuntu 18.04" --archs "x86_64" --file /etc/pts/oval/bionic-oval.xml --debug 2 \
     2> /etc/pts/oval/bionic-oval.log

$CMD --os "Ubuntu 16.04" --archs "x86_64" --file /etc/pts/oval/xenial-oval.xml --debug 2 \
     2> /etc/pts/oval/xenial-oval.log

$CMD --os "Debian 9.0" --archs "x86_64 armhf" --file /etc/pts/oval/stretch-oval.xml --debug 2 \
     2> /etc/pts/oval/stretch-oval.log

$CMD --os "Debian 8.0" --archs "x86_64 armhf" --file /etc/pts/oval/jessie-oval.xml --debug 2 \
     2> /etc/pts/oval/jessie-oval.log

$CMD --os "Debian 7.0" --archs "x86_64 armhf" --file /etc/pts/oval/wheezy-oval.xml --debug 2 \
     2> /etc/pts/oval/wheezy-oval.log


if [ $DEL_LOG -eq 1 ]
then
  rm $CMD_LOG
  echo "no new vulnerabilities found"
fi
