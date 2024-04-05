#!/bin/bash
read -p "Please Enter Elf Path:" -r r1
# Check if the file exists
if [ ! -f "$r1" ]; then
    echo "Error: File not found at $r1"
    exit 1
fi
arm-none-eabi-gdb "$r1"
