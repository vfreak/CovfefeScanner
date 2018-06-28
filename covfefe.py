#!/bin/python3
import subprocess
import argparse
import requests
import time
import xml.etree.ElementTree as ET
import os

parser = argparse.ArgumentParser()
parser.add_argument("-t", type=str, help="sets the target host for the audit")
parser.add_argument("-L", type=str, help="sets a file to use as a list of targets")
parser.add_argument("-R", action='store_true', help="launch all recon tools")
parser.add_argument("-S", action='store_true', help="launch all scanning tools")
parser.add_argument("-A", action='store_true', help="launch all attack tools (requires nmap scan data)")
args = parser.parse_args()

lootpath = os.getenv("HOME") + "/.covfefe"

userlist = "/usr/share/usernames.txt"
passlist = "/usr/share/passwords.txt"

#
# Boring formatting stuff that makes things somewhat bearable to look at.
#

def banner():
	print("-[-]-[-]             ______________________         [-]-[-]-")
	print("[-]-[-]             (___________           |         [-]-[-]")
	print("-[-]-[-]              [XXXXX]   |          |        [-]-[-]-")
	print("[-]-[-]          __  /~~~~~~~\  | COVFEFE  |         [-]-[-]")
	print("-[-]-[-]        /  \|@@@@@@@@@\ |          |        [-]-[-]-")
	print("[-]-[-]         \   |@@@@@@@@@@|| Scanner  |         [-]-[-]")
	print("-[-]-[-]            \@@@@@@@@@@||  ______  |        [-]-[-]-")
	print("[-]-[-]              \@@@@@@@@/ ||scan|pwn||         [-]-[-]")
	print("-[-]-[-]            __\@@@@@@/__|  ~~~~~~  |        [-]-[-]-")
	print("[-]-[-]            (____________|__________|         [-]-[-]")
	print("-[-]-[-]           |_______________________|        [-]-[-]-")
	print("[-]-[-]      Loot path:~/.covfefe                    [-]-[-]\n")

def printmsg(msg):
	print("\033c")
	banner()
	size = 0
	while len(msg) + size < 60:
		if len(msg) + size < 50:
			size += 8
		elif len(msg) % 2 != 0:
			msg = msg + " "
		else:
			msg = " " + msg

	print("\n{}{}{}\n".format("-[-]" * int(size/8), msg, "[-]-" * int(size/8)))

def scrolltext(text):
	output = text.split("\n")
	for i in range(0,len(output)):
		time.sleep(0.01)
		if i >= 48:
			if i % 48 == 0:
				print("\033c")
				banner()
			print(output[i])
		else:
			print(output[i])


#
# Utility functions that make things easiers.
#

def osrun(cmd):
	arguments = cmd.split()
	return subprocess.run(arguments, stdout=subprocess.PIPE).stdout.decode("utf-8")

def leave():
	response = input("		Continue anyways? y/N ")
	if response.lower() == "y":
		return
	else:
		exit()

#
# Functions for running various OSINT scans.
#

def dnsenum(target):
	printmsg("Running dnsenum against: {}".format(target))
	time.sleep(1)
	output = osrun("dnsenum {} -f /usr/share/dnsenum/dns.txt -o {}/{}/.dnsenum.xml".format(target, lootpath, target))
	f = open("{}/{}/dnsenum.txt".format(lootpath, target), "w+")
	f.write(output)
	f.close()
	flag = False
	scrolltext(output)
	time.sleep(1)

#
# Functions for running various service scans.
#

def portscan(target):
	printmsg("Running port scan against {}".format(target))
	time.sleep(1)
	filename = "{}/{}/.nmap.xml".format(lootpath, target, target)
	output = osrun("sudo nmap -sV -sC -O --open {} -oX {}".format(target, filename))
	f = open("{}/{}/nmap.txt".format(lootpath, target, target), "w+")
	f.write(output)
	f.close()
	scrolltext(output)
	time.sleep(1)
	return filename

def sshscan(target, port):
	printmsg("Running ssh-audit against: {}".format(target))
	time.sleep(1)
	output = osrun("ssh-audit {} -p {}".format(target, port))
	f = open("{}/{}/ssh-audit.txt".format(lootpath, target, target, port), "w+")
	f.write(output)
	f.close()
	flag = False
	scrolltext(output)
	time.sleep(1)

def sslscan(target, port):
	printmsg("Running sslscan against {}".format(target))
	time.sleep(1)
	output = osrun("sslscan {}:{}".format(target, port))
	f = open("{}/{}/sslscan.txt".format(lootpath, target, target, port), "w+")
	f.write(output)
	f.close()
	scrolltext(output)
	time.sleep(1)

def getheaders(target, port, https):
	printmsg("Grabbing all http headers from {}".format(target))
	if https:
		output = osrun("curl --insecure -I https://{}:{}".format(target, port))
	else:
		output = osrun("curl -I http://{}:{}".format(target, port))
	
	f = open("{}/{}/headers-{}.txt".format(lootpath, target, port), "w+")
	f.write(output)
	f.close()
	scrolltext(output)
	time.sleep(1)

def checkport(xmlfile, service):
	ports = []
	tree = ET.parse(xmlfile)
	root = tree.getroot()
	for hosts in root.findall("host"):
		for p in hosts.find("ports").findall("port"):
			if p.find("service").get("name") == service:
				ports.append(p.get("portid"))
	return ports

#
# Functions for running various attacks.
#

def bruteall(xmlfile, target):
	printmsg("Running ncrack brute force against: {}".format(target))
	output = osrun("ncrack -f -U {} -P {} -iX {} -v -oN {}/{}/ncrack -oX {}/{}/.ncrack".format(userlist, passlist, xmlfile, lootpath, target, lootpath, target))
	scrolltext(output)

#
# Functions for running groups of modules.
#

def recon(host):
	dnsenum(host)


def scan(host):
	xml = portscan(host)

	for p in checkport(xml, "ssh"):
		sshscan(host, p)
	for p in checkport(xml, "ssl"):
		sslscan(host, p)
		getheaders(host, p, True)
	for p in checkport(xml, "http"):
		getheaders(host, p, False)

def attack(host):
	bruteall("{}/{}/.nmap.xml".format(lootpath, host, host), host)

#
# Install function for distros with apt package managers.
#

def install():
	printmsg("Checking for required tools and modules.")
	needed = []
	time.sleep(0.5)

	if os.path.isfile("/usr/bin/dnsenum"):
		print("[x] dnsenum installed!")
		time.sleep(0.5)
	else:
		print("[ ] dnsenum not installed!")
		needed.append("sudo apt-get --assume-yes install dnsenum")
		time.sleep(0.5)

	if os.path.isfile("/usr/bin/nmap"):
		print("[x] nmap installed!")
		time.sleep(0.5)
	else:
		print("[ ] nmap not installed!")
		needed.append("sudo apt-get --assume-yes install nmap")
		time.sleep(0.5)

	if os.path.isfile("/usr/bin/ssh-audit"):
		print("[x] ssh-audit installed!")
		time.sleep(0.5)
	else:
		print("[ ] ssh-audit not installed!")
		needed.append("sudo apt-get --assume-yes install ssh-audit")
		time.sleep(0.5)

	if os.path.isfile("/usr/bin/sslscan"):
		print("[x] sslscan installed!")
		time.sleep(0.5)
	else:
		print("[] sslscan not installed!")
		needed.append("sudo apt-get --assume-yes install sslscan")
		time.sleep(0.5)

	if os.path.isfile("/usr/bin/curl"):
		print("[x] curl installed!")
		time.sleep(0.5)
	else:
		print("[] curl not installed!")
		needed.append("sudo apt-get --assume-yes install curl")
		time.sleep(0.5)

	if os.path.isfile("/usr/bin/ncrack"):
		print("[x] ncrack installed!\n")
		time.sleep(0.5)
	else:
		print("[ ] ncrack not installed!\n")
		needed.append("sudo apt-get --assume-yes install ncrack")

	time.sleep(1)

	if len(needed) != 0:
		leave()
		for command in needed:
			osrun(command)
		printmsg("All packages installed.")
	else:
		printmsg("All packages already installed.")
	time.sleep(1)

#
# Main function that kicks it all off.,
#

def main():
	banner()
	install()
	targets = []
	if args.t and args.L:
		printmsg("ERROR: You cannot use both list and target!")
		exit()
	elif args.t:
		targets.append(args.t)
	elif args.L:
		for t in open(args.L):
			targets.append(t[:-1])
	else:
		printmsg("ERROR: Please specify either a target or a list!")
		exit()

	for host in targets:
		time.sleep(1)

		if os.path.isdir("{}/{}".format(lootpath, host)):
			if input("A loot folder already exist for this host. Overwite? y/N ").lower() != "y":
				continue
		else:
			osrun("mkdir {}/{}".format(lootpath, host))

		if args.R:
			recon(host)
		
		if args.S:
			scan(host)

		if args.A and os.path.exists("{}/{}/.nmap.xml".format(lootpath, host, host)):
			attack(host)
		elif args.A:
			printmsg("No scan data found for host: {}".format(host))
		time.sleep(1)

main()
