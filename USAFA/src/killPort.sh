#!/bin/bash

clear
echo -e "Do you want to kill a port? 'y' or 'n'.\n" 
read killPort

while [ "$killPort" != "n" ]; do

	echo -e "\nType the port you want to locate and kill.\n gdb connections - port 3333.\n tcl connections - port 6666.\n telnet connections - port 4444.\n"
	read portNumber

	sudo lsof -i :"$portNumber"


	echo "NOTE: If there is no output with no output, the port isn't open"
	echo "Type the PID to kill"
	read PID

	kill -9 "$PID"
	
	echo "Do you want to kill another port? 'y' or 'n'"
	read killPort
done
