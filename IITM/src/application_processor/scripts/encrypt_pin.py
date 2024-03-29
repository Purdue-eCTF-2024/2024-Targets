import hashlib
import random
import sys

#first argument is location of the file, secomd is the location of the new file

ectf_params_file = sys.argv[1]
f2 = open(sys.argv[2], 'w')

def sha3_256_hash(message):
    sha3_hash = hashlib.sha3_256()
    sha3_hash.update(message)
    return sha3_hash.digest()


with open(ectf_params_file, 'r') as f:
    lines = f.readlines()
    
    
    for line in lines:
        if "#define AP_PIN" in line:
            salt = random.randbytes(32)
            f2.write("#define PIN_SALT" + ' ')
            for i in salt:
                f2.write(f'{i},')
            f2.write("\n")
            f2.write("#define AP_PIN_HASH" + ' ')
            pin_hash = (sha3_256_hash(bytearray(line.split()[-1][1:-1], "ascii")+salt))
            for i in pin_hash:
                f2.write(f'{i},')
            f2.write("\n")
            
        elif "#define AP_TOKEN" in line:
            salt = random.randbytes(32)
            f2.write("#define TOKEN_SALT" + ' ')
            for i in salt:
                f2.write(f'{i},')
            f2.write("\n")
            f2.write("#define AP_TOKEN_HASH" + ' ') 
            token_hash = (sha3_256_hash(bytearray(line.split()[-1][1:-1], "ascii") + salt))
            for i in token_hash:
                f2.write(f'{i},')
            f2.write("\n")
    f2.close()
