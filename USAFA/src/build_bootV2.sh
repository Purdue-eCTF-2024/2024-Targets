#!/bin/bash

echo "Do you want to build enviroment? 'y' or 'n'"
read c

if [ "$c" = "y" ]
then
ectf_build_depl -d ../ecft

ectf_build_ap -d ../ecft -on ap --p 123456 -c 2 -ids "0x11111124, 0x11111125" -b "Test boot message" -t 0123456789abcdef -od build

ectf_build_comp -d ../ecft -on comp1 -od build -id 0x11111124 -b "Component boot" -al "McLean" -ad "08/08/08" -ac "Fritz"

ectf_build_comp -d ../ecft -on comp2 -od build -id 0x11111125 -b "Component boot" -al "McLean" -ad "08/08/08" -ac "Fritz"
fi


####### OS
echo "If on mac enter 'm', for ubuntu 'u'"
read b

####### Devices to skip
echo "enter 0 to boot all, 1 to skip first device, and 2 to skip first two devices"
read s

######## OS
# # Ubuntu
if [ "$b" = "u" ] 
then
echo "............Ubuntu......................"
echo " "
echo "----------In order for this to work reset 1 device at a time----------"
echo "------------------Disconnect all devices initially--------------------"

if [ "$s" = "0" ] 
then
#boot comp1
echo "Press enter when ACM0 connected and in reset mode. Comp1"
read z
ectf_update --infile build/comp1.img --port /dev/ttyACM0
fi

if [ "$s" = "0" ] || [ "$s" = "1" ]
then
#boot comp2
echo "Press enter when ACM1 connected and in reset mode. Comp2"
read z
ectf_update --infile build/comp2.img --port /dev/ttyACM1
fi

#boot AP
echo "Press enter when ACM2 connected and in reset mode. AP"
read z
ectf_update --infile build/ap.img --port /dev/ttyACM2

echo "Press enter for list check for ap"
read z
ectf_list -a /dev/ttyACM2

echo "Press enter for boot"
read z
ectf_boot -a /dev/ttyACM2


elif [ "$b" = "m" ] 
then
echo "                   No Mac yet :(                  "
fi