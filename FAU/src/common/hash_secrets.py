def hash_value(value):
    return hashlib.sha512(value.encode()).digest().hex()

def update_file(file_path, pin_hash, token_hash):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    with open(file_path, 'w') as file:
        for line in lines:
            if line.strip().startswith('#define AP_PIN'):
                file.write(f'#define AP_PIN "{pin_hash}"\n')
            elif line.strip().startswith('#define AP_TOKEN'):
                file.write(f'#define AP_TOKEN "{token_hash}"\n')
            else:
                file.write(line)

def main():
    file_path = '../application_processor/inc/ectf_params.h'
    ap_pin = None
    ap_token = None

    with open(file_path, 'r') as file:
        for line in file:
            if line.strip().startswith('#define AP_PIN'):
                ap_pin = line.split('"')[1]
            elif line.strip().startswith('#define AP_TOKEN'):
                ap_token = line.split('"')[1]

    if ap_pin and ap_token:
        pin_hash = hash_value(ap_pin)
        token_hash = hash_value(ap_token)
        update_file(file_path, pin_hash, token_hash)

if __name__ == '__main__':
    import os
    import sys
    import hashlib

    if sys.argv[1] == 'AP':
        main()
