poetry run ectf_build_ap -d ../2024-ectf -on ap --p 123456 -c 2 -ids "0x11111124, 0x11111125" -b "Test boot message" -t 0123456789abcdef -od build &&
poetry run ectf_update --infile build/ap.img --port /dev/tty.usbmodem11102