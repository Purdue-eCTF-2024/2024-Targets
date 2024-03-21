#!/usr/bin/env python3
# Author: utaha1228
# MIT TechSec

KEY_SIZE = 32
SALT_SIZE = 32
OUTPUT_FILE = "global_secrets.h"

with open("/dev/random", "rb") as f:
    secret  = f.read(KEY_SIZE).hex()
    attest  = f.read(SALT_SIZE).hex()
    replace = f.read(SALT_SIZE).hex()

secret_c_str  = "".join(["\\x" +  secret[i:i+2] for i in range(0,  len(secret), 2)])
attest_c_str  = "".join(["\\x" +  attest[i:i+2] for i in range(0,  len(attest), 2)])
replace_c_str = "".join(["\\x" + replace[i:i+2] for i in range(0, len(replace), 2)])

output = f"""\
#define SHARED_SECRET_KEY (uint8_t *)("{secret_c_str}")
#define ATTEST_SALT  "{attest_c_str}"
#define REPLACE_SALT "{replace_c_str}"
"""

with open(OUTPUT_FILE, "w") as f:
	f.write(output)
