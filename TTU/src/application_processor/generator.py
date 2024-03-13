#!/usr/bin/env python3

import re
import hashlib

# The purpose of this script is to hash the AP_PIN and AP_TOKEN in the ectf_params.h file
# By default, the Host Tools write the AP_PIN and AP_TOKEN to the ectf_params.h file in plaintext
# This script is invoked during the build process to hash the AP_PIN and AP_TOKEN using a pepper

def define_to_dict(path: str) -> dict:
    ret = {}
    try:
        with open(path, "r") as f:
            text = f.read()
            matches = re.findall(r'#define (.*) "(.*)"', text)
            for match in matches:
                ret[match[0]] = match[1]
        print(ret)
    except:
        print(f"Error reading file {path}")
        exit(1)
    return ret

def update_ectf_params(filename: str, pepper: str):
    text = None
    try:
        with open(filename, 'r') as f:
            text = f.read()
    except:
        print(f"Error reading file {filename}")
        exit(1)
    # Extract the AP_PIN and AP_TOKEN from the file
    ap_pin = re.search(r'#define AP_PIN "(.*)"', text).group(1)
    ap_token = re.search(r'#define AP_TOKEN "(.*)"', text).group(1)
    # Hash the AP_PIN and AP_TOKEN using the pepper
    ap_pin = hashlib.sha256(ap_pin.encode('utf-8') + pepper.encode('utf-8')).hexdigest()
    ap_token = hashlib.sha256(ap_token.encode('utf-8') + pepper.encode('utf-8')).hexdigest()
    # Replace the AP_PIN and AP_TOKEN in the file
    text = re.sub(r'#define AP_PIN "(.*)"', f'#define AP_PIN "{ap_pin}"', text)
    text = re.sub(r'#define AP_TOKEN "(.*)"', f'#define AP_TOKEN "{ap_token}"', text)

    try:
        with open(filename, 'w') as f:
            f.write(text)
    except:
        print(f"Error writing file {filename}")
        exit(1)
    return
    
def main():
    global_secrets = define_to_dict("../deployment/global_secrets.h")
    update_ectf_params("./inc/ectf_params.h", global_secrets["HASH_PEPPER"])
    return
    
if __name__ == "__main__":
    main()
    
    
    


    
    