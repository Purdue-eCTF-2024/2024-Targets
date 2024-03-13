import time
import subprocess
import os
import hashlib

# This script is for testing the bruteforce protection of attestation and replacement
# env = os.environ.copy()
# cmd = "python3 build.py --attest -s /dev/tty.usbmodem112402 -c 0x11111124 --pin 12345"
# start = time.time()
# subprocess.run(cmd, shell=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) # initial "Invalid PIN!" message
# while ("Invalid PIN!" not in subprocess.run(cmd, shell=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode('utf-8')):
#     continue
# end = time.time()
# print("Time: ", end - start)

# This is for testing the component hashing
# tbh idk why it isn't working in C :(
component_id = "0xa67adb66"
pepper = "Z4j4SuLUd5"
string = component_id + pepper
sha = hashlib.sha256(string.encode('utf-8')).hexdigest()
print(sha)

