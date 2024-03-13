poetry run ectf_build_comp -d ../2024-ectf -on comp0 -od build -id 0x11111124 -b "Component boot" -al "McLean" -ad "08/08/08" -ac "Fritz" &&
poetry run ectf_build_comp -d ../2024-ectf -on comp1 -od build -id 0x11111125 -b "Component boot" -al "McLean" -ad "08/08/08" -ac "Fritz" &&

poetry run ectf_update --infile build/comp0.img --port /dev/tty.usbmodem11402 &&
poetry run ectf_update --infile build/comp1.img --port /dev/tty.usbmodem11302