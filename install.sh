#!/bin/bash

mkdir ~/.covfefe

if [[ $EUID -ne 0 ]]; then
	echo "This script must be ran as sudo/root"
fi

sudo mkdir /usr/share/covfefe
sudo cp $PWD/covfefe.py /usr/bin/covfefe
sudo cp $PWD/usernames.txt /usr/share/covfefe
sudo cp $PWD/passwords.txt /usr/share/covfefe
sudo cp $PWD/LICENSE /usr/share/covfefe
