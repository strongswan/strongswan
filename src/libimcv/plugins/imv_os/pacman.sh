#!/bin/sh

DATE=`date +%Y%m%d`
DEBIAN=http://packages.debian.org
UBUNTU=http://packages.ubuntu.com
UBUNTU_VERSIONS="quantal precise oneiric lucid"
PACKAGES=allpackages?format=txt.gz

for v in $UBUNTU_VERSIONS
do
  wget $UBUNTU/$v/$PACKAGES -O $DATE-$v.txt.gz
  wget $UBUNTU/$v-updates/$PACKAGES -O $DATE-$v-updates.txt.gz
done

wget $DEBIAN/stable/$PACKAGES -O $DATE-squeeze.txt.gz
gunzip *.gz

ipsec pacman --product "Ubuntu 12.10" --file $DATE-quantal.txt
echo
ipsec pacman --product "Ubuntu 12.10" --file $DATE-quantal-updates.txt --update
echo
ipsec pacman --product "Ubuntu 12.04" --file $DATE-precise.txt
echo
ipsec pacman --product "Ubuntu 12.04" --file $DATE-precise-updates.txt --update
echo
ipsec pacman --product "Ubuntu 11.10" --file $DATE-oneiric.txt
echo
ipsec pacman --product "Ubuntu 11.10" --file $DATE-oneiric-updates.txt --update
echo
ipsec pacman --product "Ubuntu 10.04" --file $DATE-lucid.txt
echo
ipsec pacman --product "Ubuntu 10.04" --file $DATE-lucid-updates.txt --update
echo
ipsec pacman --product "Debian squeeze" --file $DATE-squeeze.txt

cp config.db config.db-$DATE
