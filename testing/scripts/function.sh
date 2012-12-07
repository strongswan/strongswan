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

export TERM=xterm
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
NORMAL=$(tput op)

# exit with given error message
# $1 - error message
die() {
	echo -e "${RED}$1${NORMAL}"
	exit 1
}

[ -f testing.conf ] || die "Configuration file 'testing.conf' not found"
. testing.conf

# execute command
# $1 - command to execute
# $2 - whether or not to log command exit status
#      (0 -> disable exit status logging)
execute()
{
	cmd=${1}
	echo $cmd >>$LOGFILE 2>&1
	$cmd >>$LOGFILE 2>&1
	status=$?
	[ "$2" != 0 ] && log_status $status
	if [ $status != 0 ]; then
		echo
		echo "! Command $cmd failed, exiting (status $status)"
		echo "! Check why here $LOGFILE"
		exit 1
	fi
}

# execute command in chroot
# $1 - command to execute
execute_chroot()
{
	execute "chroot $LOOPDIR $@"
}

# write green status message to console
# $1 - msg
echo_ok()
{
	echo -e "${GREEN}$1${NORMAL}"
}

# write red status message to console
# $1 - msg
echo_failed()
{
	echo -e "${RED}$1${NORMAL}"
}

function cecho {
    echo -e "\033[1;31m$1\033[0m"
}
function cgecho {
    echo -e "\033[1;32m$1\033[0m"
}

function cecho-n {
    echo -en "\033[1;31m$1\033[0m"
}

# log an action
# $1 - current action description
log_action()
{
	/bin/echo -n "[....] $1 "
}

# log an action status
# $1 - exit status of action
log_status()
{
	tput hpa 0
	if [ $1 -eq 0 ]; then
		/bin/echo -ne "[${GREEN} ok ${NORMAL}"
	else
		/bin/echo -ne "[${RED}FAIL${NORMAL}"
	fi
	echo
}

# the following two functions are stolen from [1]
# [1] - http://www.linuxjournal.com/content/use-bash-trap-statement-cleanup-temporary-files

declare -a on_exit_items

# perform registered actions on exit
on_exit()
{
	for i in "${on_exit_items[@]}"
	do
		eval $i >>$LOGFILE 2>&1
	done
	on_exit_items=""
	trap - EXIT
}

# register a command to execute when the calling script terminates. The
# registered commands are called in FIFO order.
# $* - command to register
do_on_exit()
{
	local n=${#on_exit_items[*]}
	on_exit_items[$n]="$*"
	if [ $n -eq 0 ]; then
		trap on_exit EXIT
	fi
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


    ###########################################
    # search and replace in each found file the
    # given string
    #

    for eachfoundfile in `find $DESTDIR -type f`
    do
        sed -i -e "s/$SEARCHSTRING/$REPLACESTRING/g" "$eachfoundfile"
    done

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

