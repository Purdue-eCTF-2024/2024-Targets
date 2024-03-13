#!/usr/bin/env python3

import os
import subprocess
import dotenv
import argparse
import sys

# Check for .env and stop if not found
if not os.path.exists(".env"):
    print(".env was not found. Please create a .env file in the root directory of the project.")
    sys.exit(1)

dotenv.load_dotenv()

PIN=os.environ.get('PIN')
COMPONENT_CNT=os.environ.get('COMPONENT_CNT')
COMPONENT_IDS=os.environ.get('COMPONENT_IDS')
BOOT_MESSAGE=os.environ.get('BOOT_MESSAGE')
TOKEN=os.environ.get('TOKEN')
COMPONENT_BOOT_MESSAGE=os.environ.get('COMPONENT_BOOT_MESSAGE')
ATTESTATION_LOCATION=os.environ.get('ATTESTATION_LOCATION')
ATTESTATION_CUSTOMER=os.environ.get('ATTESTATION_CUSTOMER')
ATTESTATION_DATE=os.environ.get('ATTESTATION_DATE')

def run(cmd: str):
    print(cmd)
    subprocess.run(cmd, shell=True, check=True)

def build_deployment():    
    run("poetry run ectf_build_depl -d ./")

parser = argparse.ArgumentParser()
parser.add_argument('-b', '--build', choices=['ap', 'comp'])
parser.add_argument('-c', '--component')
parser.add_argument('-f', '--flash', choices=['ap', 'comp'])
parser.add_argument('-s', '--serial')
parser.add_argument('--pin')
parser.add_argument('--list', action='store_true')
parser.add_argument('--attest', action='store_true')
parser.add_argument('--boot', action='store_true')
parser.add_argument('--debug', action='store_true')

args = parser.parse_args()

if args.build:
    if args.build == "ap":
        build_deployment()
        run(f"poetry run ectf_build_ap -d ./ -on ap --p {PIN} -c {COMPONENT_CNT} -ids '{COMPONENT_IDS}' -b '{BOOT_MESSAGE}' -t {TOKEN} -od build")
    elif args.build == "comp":
        if args.component and args.component in COMPONENT_IDS.split(', '):
            build_deployment()
            run(f"poetry run ectf_build_comp -d ./ -on comp -od build/{args.component} -id {args.component} -b '{COMPONENT_BOOT_MESSAGE}' -al '{ATTESTATION_LOCATION}' -ad '{ATTESTATION_DATE}' -ac '{ATTESTATION_CUSTOMER}'")
        else:
            print(f"Must specify component ID (--component). Valid options are: {COMPONENT_IDS}")

elif args.flash:
    if args.flash == "ap":
        if args.serial:
            run(f"poetry run ectf_update --infile ./build/ap.img --port {args.serial}")
        else:
            print(f"Must specify serial port of AP (--serial).")
    elif args.flash == "comp":
        if args.component and args.component in COMPONENT_IDS.split(', '):
            if args.serial:
                run(f"poetry run ectf_update --infile ./build/{args.component}/comp.img --port {args.serial}")
            else:
                print(f"Must specify serial port of AP (--serial).")
        else:
            print(f"Must specify component ID (--component). Valid options are: {COMPONENT_IDS}")

elif args.list:
    if args.serial:
        run(f"poetry run ectf_list -a {args.serial}")
    else:
        print(f"Must specify serial port of AP (--serial).")

elif args.attest:
    if args.serial:
        if args.component and args.component in COMPONENT_IDS.split(', '):
            if args.pin:
                run(f"poetry run ectf_attestation -a {args.serial} -c {args.component} -p {args.pin}")
            else:
                print(f"Must specify PIN for component (--pin).")
        else:
            print(f"Must specify component ID (--component). Valid options are: {COMPONENT_IDS}")
    else:
        print(f"Must specify serial port of AP (--serial).")

elif args.boot:
    if args.serial:
        run(f"poetry run ectf_boot -a {args.serial}")
    else:
        print(f"Must specify serial port of AP (--serial).")
    
elif args.debug:
    #run("openocd -f ./openocd/tcl/interface/cmsis-dap.cfg -f ./openocd/tcl/target/max78000.cfg -c 'init; reset; halt'")
    run("openocd -f interface/cmsis-dap.cfg -f target/max78000.cfg -c 'init; reset; halt'")
    
else:
    print(parser.print_usage())    
    
    
    
    
    
    
    


