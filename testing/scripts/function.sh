#!/bin/bash
# provides some general-purpose script functions
#
# Copyright (C) 2004  Eric Marchionni, Patrik Rayo
# Zuercher Hochschule Winterthur
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# RCSID $Id$


############################################
# print output in color
#

function cecho {
    echo -e "\033[1;31m$1\033[0m"
}
function cgecho {
    echo -e "\033[1;32m$1\033[0m"
}

function cecho-n {
    echo -en "\033[1;31m$1\033[0m"
}


#############################################
# output all args to stderr and exit with
# return code 1
#

die() {
    echo $* 1>&2
    exit 1
}

#############################################
# search and replace strings throughout a
# whole directory
#

function searchandreplace {

    SEARCHSTRING="$1"
    REPLACESTRING="$2"
    DESTDIR="$3"

    [ -d "$DESTDIR" ] || die "$DESTDIR is not a directory!"


    #########################
    # create a temporary file
    #

    TMPFILE="/tmp/sr.$$"


    ###########################################
    # search and replace in each found file the
    # given string
    #

    for eachfoundfile in `find $DESTDIR -type f`
    do
        sed -e "s/$SEARCHSTRING/$REPLACESTRING/g" "$eachfoundfile" > "$TMPFILE"
        cp -f "$TMPFILE" "$eachfoundfile"
    done


    ###########################
    # delete the temporary file
    #

    rm -f "$TMPFILE"

}

#############################################
# add a bridge
#

function umlbr_add {
	brctl addbr     "umlbr$1"
	brctl setfd     "umlbr$1" 0
	brctl setageing "umlbr$1" 3600
	brctl stp       "umlbr$1" off
	ifconfig        "umlbr$1" "$2" netmask "$3" up 
}

#############################################
# delete a bridge
#

function umlbr_del {
	ifconfig    "umlbr$1" down                     &> /dev/null 2>&1
	brctl delbr "umlbr$1"                          &> /dev/null 2>&1
}

#############################################
# add a tap interface to a bridge
#

function umlbr_add_tap {
	tunctl -t "tap$1_$2"                           &> /dev/null 2>&1
	ifconfig "tap$1_$2" 0.0.0.0 promisc up         &> /dev/null 2>&1
	brctl addif "umlbr$1" "tap$1_$2"               &> /dev/null 2>&1
	cecho-n "$2.."
 }

#############################################
# delete a tap interface from a bridge
#

function umlbr_del_tap {
	ifconfig "umlbr$2" down                        &> /dev/null 2>&1
	brctl delif "umlbr$1" "tap$1_$2"               &> /dev/null 2>&1
	tunctl -d "tap$1_$2"                           &> /dev/null 2>&1
	cecho-n "$2.."
 }

