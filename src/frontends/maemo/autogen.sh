#!/bin/sh
libtoolize --force &&
aclocal &&
automake -a &&
autoconf
