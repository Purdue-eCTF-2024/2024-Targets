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

######## OS
# # Ubuntu
if [ "$b" = "u" ]
then
echo "............Ubuntu......................"
echo " "
echo "----------In order for this to work reset 1 device at a time----------"
echo "------------------Disconnect all devices initially--------------------"
# echo "Enter 'y' when ACMO connected and in reset mode. Comp1"
echo "Press enter when ACM0 connected and in reset mode. Comp1"
read z
# if [ "$z" = "y" ]
# then
ectf_update --infile build/comp1.img --port /dev/ttyACM0
# fi

# echo "Enter 'y' when ACM1 connected and in reset mode. Comp2"
echo "Press enter when ACM1 connected and in reset mode. Comp2"
read z
# if [ "$z" = "y" ]
# then
ectf_update --infile build/comp2.img --port /dev/ttyACM1
# fi


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