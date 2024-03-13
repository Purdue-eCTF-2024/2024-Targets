#!/usr/bin/env python3

# The purpose of this script is to populate the global_secrets.h file
# global_secrets.h is made available to both the AP and Component(s)

import os
import random
import string

def generate_random(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for i in range(length))

# Create sample .env so compiler doesn't fail
# This is mainly for the testing service to work
if not os.path.exists("../.env"):
    print(".env not found, creating sample .env")
    with open("../.env", "w") as f:
        f.write("PIN=\"123456\"\n")
        f.write("TOKEN=\"0123456789abcdef\"\n")
        f.write("COMPONENT_CNT=\"2\"\n")
        f.write("COMPONENT_IDS=\"0x11111124, 0x11111125\"\n")
        f.write("BOOT_MESSAGE=\"Test boot message\"\n")
        f.write("COMPONENT_BOOT_MESSAGE=\"Component boot\"\n")
        f.write("ATTESTATION_LOCATION=\"McLean\"\n")
        f.write("ATTESTATION_DATE=\"08/08/08\"\n")
        f.write("ATTESTATION_CUSTOMER=\"Fritz\"\n")

HASH_PEPPER=generate_random(10)
ENCRYPTION_KEY=generate_random(32)
AP_FIRMWARE_TOKEN=generate_random(32) # This is used to let components ensure the AP is authentic
COMPONENT_FIRMWARE_TOKEN=generate_random(32) # This is used to let the AP ensure the components are authentic

with open("./global_secrets.h", "w") as f:
    f.write(f"#define HASH_PEPPER \"{HASH_PEPPER}\"\n")
    f.write(f"#define ENCRYPTION_KEY \"{ENCRYPTION_KEY}\"\n")
    f.write(f"#define AP_FIRMWARE_TOKEN \"{AP_FIRMWARE_TOKEN}\"\n")
    f.write(f"#define COMPONENT_FIRMWARE_TOKEN \"{COMPONENT_FIRMWARE_TOKEN}\"\n")