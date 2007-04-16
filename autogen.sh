#!/bin/sh
libtoolize &&
aclocal &&
automake -a &&
autoconf

