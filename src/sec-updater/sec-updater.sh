#!/bin/sh

DIR="/etc/pts"
DATE=`date +%Y%m%d-%H%M`
UBUNTU="http://security.ubuntu.com/ubuntu/dists"
UBUNTU_VERSIONS="xenial"
UBUNTU_DIRS="main multiverse restricted universe"
UBUNTU_ARCH="binary-amd64"
DEBIAN="http://security.debian.org/dists"
DEBIAN_VERSIONS="jessie"
DEBIAN_DIRS="main contrib non-free"
DEBIAN_ARCH="binary-amd64"
CMD=/usr/sbin/sec-updater
CMD_LOG="$DIR/$DATE-sec-update.log"

mkdir -p $DIR/dists
cd $DIR/dists

# Download Ubuntu distribution information

for v in $UBUNTU_VERSIONS
do
  for a in $UBUNTU_ARCH
  do
    mkdir -p $v-security/$a $v-updates/$a
    for d in $UBUNTU_DIRS
    do
      wget $UBUNTU/$v-security/$d/$a/Packages.xz -O $v-security/$a/Packages-$d.xz
      unxz -f $v-security/$a/Packages-$d.xz
      wget $UBUNTU/$v-updates/$d/$a/Packages.xz  -O $v-updates/$a/Packages-$d.xz
      unxz -f $v-updates/$a/Packages-$d.xz
	done
  done
done

# Download Debian distribution information

for v in $DEBIAN_VERSIONS
do
  for a in $DEBIAN_ARCH
  do
    mkdir -p $v-updates/$a
    for d in $DEBIAN_DIRS
    do
      wget $DEBIAN/$v/updates/$d/$a/Packages.bz2  -O $v-updates/$a/Packages-$d.bz2
      bunzip2 -f $v-updates/$a/Packages-$d.bz2
	done
  done
done

# Run sec-updater in distribution information

for f in xenial-security/binary-amd64/*
do
  echo "security: $f"
  $CMD --product "Ubuntu 16.04 x86_64" --file $f --security >> $CMD_LOG 2>&1
done
echo
for f in xenial-updates/binary-amd64/*
do
  echo "updates: $f"
  $CMD --product "Ubuntu 16.04 x86_64" --file $f >> $CMD_LOG 2>&1
done
echo
for f in jessie-updates/binary-amd64/*
do
  echo "security: $f"
  $CMD --product "Debian 8.0 x86_64" --file $f --security >> $CMD_LOG 2>&1
done
