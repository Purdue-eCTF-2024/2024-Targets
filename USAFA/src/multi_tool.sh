#!/bin/bash

clear
echo -e "What tool do you want to use?\n1 - ectf_tools\n2 - initialize openOCD\n3 - initiatilize gdb\n4 - initiatilize gdb gui\n5 - Build Simple Environment\n"
read -p "Enter tool number: " -r toolUsage

if [ "$toolUsage" = "1" ]
then
    
    clear
	echo -e "What ectf_tool do you want to use\n1 - Build Deployment\n2 - Build Application Processor\n3 - Build Component\n4 - Update Tool\n5 - List Tool\n6 - Boot Tool\n7 - Replace Tool\n8 - Attestation Tool\n"
	read -p "Enter ectf tool number: " -r  ectf_tool

	if [ "$ectf_tool" = "1" ]
    then
		ectf_build_depl -d ../ecft
	elif [ "$ectf_tool" = "2" ]
    then
        clear
        echo -e "Building Application Processor Arguments\n"
		read -p "Enter the output name: "  build_ap_arg1
		read -p "Enter the pin: "  build_ap_arg2
		read -p "Enter the amount of components: "  build_ap_arg3
        read -p "Enter the ids of the components (i.e: 0x11111124, 0x11111125): "  build_ap_arg4
		read -p "Enter boot message: " build_ap_arg5
        read -p "Enter the token: "  build_ap_arg6
        read -p "Enter the output directory: " build_ap_arg7
        
        ectf_build_ap -d ../ecft -on $build_ap_arg1 --p $build_ap_arg2 -c $build_ap_arg3 -ids "$build_ap_arg4" -b "$build_ap_arg5" -t $build_ap_arg6 -od $build_ap_arg7
    elif [ "$ectf_tool" = "3" ]
    then
        echo -e "Building Component Arguments\n"
        read -p "Enter the output name: "  build_comp_arg1
        read -p "Enter the output directory: "  build_comp_arg2
        read -p "Enter the component id: "  build_comp_arg3
        read -p "Enter boot message: "  build_comp_arg4
        read -p "Enter the attestation location: "  build_comp_arg5
        read -p "Enter the attestation date: "  build_comp_arg6
        read -p "Enter the attestation customer: " build_comp_arg7
        ectf_build_comp -d ../ecft -on $build_comp_arg1 -od $build_comp_arg2 -id $build_comp_arg3 -b "$build_comp_arg4" -al "$build_comp_arg5" -ad "$build_comp_arg6" -ac "$build_comp_arg7"
        
    elif [ "$ectf_tool" = "4" ]
    then
        echo -e "Update Tool In Usage\n"
        read -p "Enter path to the input binary: " update_tool_arg1
        read -p "Enter serial port: " update_tool_arg2
        ectf_update --infile update_tool_arg1 --port update_tool_arg2
        
    elif [ "$ectf_tool" = "5" ]
    then
        echo -e "Press ENTER to check the provisioned and found components for the AP\n"
        read -p "Enter serial port: " list_tool
        ectf_list -a $list_tool
    
    elif [ "$ectf_tool" = "6" ]
    then
        echo -e "Press ENTER to boot the system\n"
        read -p "Enter serial port: " boot_tool
        ectf_boot -a boot_tool
    
    elif [ "$ectf_tool" = "7" ]
    then
        echo -e "Replace Tool In Usage\n"
        read -p "Enter Token: " replace_tool_arg1
        read -p "Enter Component ID of the new component: " replace_tool_arg2
        read -p "Enter Component ID of the componet being replaced: " replace_tool_arg3
        ectf_replace -a /dev/ttyACM2 -t replace_tool_arg1 -i replace_tool_arg2 -o replace_tool_arg3
    
    elif [ "$ectf_tool" = "8" ]
    then
        echo -e "Attestation Tool In Usage\n"
        read -p "Enter PIN: " attestation_tool_arg1
        read -p "Enter Component ID of the target component: " attestation_tool_arg2
        ectf_attestation -a /dev/ttyACM2 -p attestation_tool_arg1 -c attestation_tool_arg2
fi
fi

if [ "$toolUsage" = "2" ]
then
    echo -e "Initializing openOCD\n"
    clear
    openocd -f interface/cmsis-dap.cfg -f target/max78000.cfg -c "init"
    fi

#
if [ "$toolUsage" = "3" ]
then
    echo -e "Initializing gdb in progress\n"
    read -p "Please Enter Elf Path: " -r r1
    elfpath=$(dirname "$r1")
    arm-none-eabi-gdb "$elfpath"
    fi

if [ "$toolUsage" = "4" ]
then
    echo -e "Initializing gdb gui in progress\n"
    read -p "Please Enter Elf Path: " -r r1
    elfpath=$(dirname "$r1")
    gdbgui --gdb $(which arm-none-eabi-gdb) "$elfpath"
    fi

if [ "$toolUsage" = "5" ]
then
    echo "Do you want to build enviroment? 'y' or 'n'"
    read c

    if [ "$c" = "y" ]
    then
        clear
        echo "------------------Building Deployment------------------"
        ectf_build_depl -d ../ecft

        clear
        echo "------------------Building Application Processor------------------"
        ectf_build_ap -d ../ecft -on ap --p 123456 -c 2 -ids "0x11111124, 0x11111125" -b "Test boot message" -t 0123456789abcdef -od build

        clear
        echo "------------------Building Component 1------------------"
        ectf_build_comp -d ../ecft -on comp1 -od build -id 0x11111124 -b "Component boot" -al "McLean" -ad "08/08/08" -ac "Fritz"

        clear
        echo "------------------Building Component 2------------------"
        ectf_build_comp -d ../ecft -on comp2 -od build -id 0x11111125 -b "Component boot" -al "McLean" -ad "08/08/08" -ac "Fritz"
    fi

    ####### Devices to skip
    clear
    echo "Enter 0 to boot all, 1 to skip first device, and 2 to skip first two devices"
    read s

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
    fi

