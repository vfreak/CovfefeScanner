#!/bin/bash

if [[ $EUID -ne 0 ]]; then
	echo "This script must be ran as root"
	exit 1
fi

cp covfefe /usr/bin/covfefe
mkdir /usr/share/covfefe
mkdir /usr/share/covfefe/loot
cp {usernames.txt,passwords.txt, LICENSE} /usr/share/covfefe
