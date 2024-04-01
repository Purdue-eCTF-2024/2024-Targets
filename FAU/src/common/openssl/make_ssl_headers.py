def txt_to_define(path: str, name: str) -> str:
    def_str = f"\n#define {name.upper()} "
    with open(path) as file:
        for line in file:
            def_str += f'"{line.strip()}" \\\n'
    return def_str[0:-3]

def write_certs_to_header(device: str, root_path: str):
    if not device in valid_devices:
        raise NameError(f"{device} not a valid device found in {valid_devices}")
    
    # Add certs/keys to secrets_<device>.h
    if not os.path.exists(f"{root_path}/inc"):
        os.mkdir(f"{root_path}/inc")

    path_root_ca = f'{os.path.dirname(root_path)}/deployment/certs/rootCA.pem'

    lines = []
    path_header = f"{root_path}/inc/secrets_{device.lower()}.h"

    path_key = f"{root_path}/build/certs/device.key"
    path_pem = f"{root_path}/build/certs/device.pem"
    lines.append(txt_to_define(path_key, 'KEY_DEVICE'))
    lines.append(txt_to_define(path_pem, 'PEM_DEVICE'))
    lines.append(txt_to_define(path_root_ca, 'PEM_CA'))

    with open(path_header, 'w') as header:
        header.writelines(lines)
        header.write('\n')

if __name__=="__main__":
    import os
    import sys

    valid_devices = ['AP', 'COMPONENT']

    for device in valid_devices:
        write_certs_to_header(sys.argv[1], sys.argv[2])
