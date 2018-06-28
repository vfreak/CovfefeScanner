#!/bin/bash

mkdir ~/.covfefe 2> /dev/null

UNAME=$(sudo whoami)

if [[ $UNAME -ne "root" ]]; then
	echo "This script must be ran as sudo/root"
	exit
fi

sudo mkdir /usr/share/covfefe 2> /dev/null
sudo cp $PWD/covfefe.py /usr/bin/covfefe
sudo cp $PWD/usernames.txt /usr/share/covfefe
sudo cp $PWD/passwords.txt /usr/share/covfefe
sudo cp $PWD/LICENSE /usr/share/covfefe

echo "Finished"
