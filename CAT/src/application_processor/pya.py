import subprocess
import hashlib
import rsa
import os

def generate_rsa_keys_and_sign():#(save_directory):
    # Generate a private key and a public key
    public_key, private_key= rsa.newkeys(2048)

    # Serialize the public key to a PEM-encoded string
    public_key_pem = rsa.PublicKey.save_pkcs1(public_key)
  
    # Save the serialized public key to a file
    # public_key_filepath = os.path.join(save_directory, "public.pem")
    with open("src/public.pem", "wb") as public_key_file:
        public_key_file.write(public_key_pem)

    # Create a hash of the component IDs
    hash_obj = hashlib.sha256()
    for id in str(comp_ids):
        hash_obj.update(id.encode())
    hashed_component_ids = hash_obj.digest()

    # Sign the component IDs
    global signature
    signature = rsa.sign(hashed_component_ids, private_key, 'SHA-256')

    # Save the signature in a .bin file
    with open('src/signature.bin', "wb") as file:
        file.write(signature)


def hash_PIN_TOKEN():
    input_file = "inc/ectf_params.h"
    output_file = "modified_ectf_params.h"

    with open(input_file, "r") as f:
        content = f.read()

    global comp_ids
    comp_ids=content.find("COMPONENT_IDS") + len("COMPONENT_IDS") + 2  # +2 to skip the quotes
    print(comp_ids)
    # Hash AP_PIN
    ap_pin_index = content.find("AP_PIN") + len("AP_PIN") + 2  # +2 to skip the quotes
    ap_pin_hash = hashlib.sha1(content[ap_pin_index:ap_pin_index + 6].encode()).hexdigest()[10:]
    ap_pin_content = f"\"{ap_pin_hash}\""

    # Hash AP_TOKEN
    ap_token_index = content.find("AP_TOKEN") + len("AP_TOKEN") + 2
    ap_token_hash = hashlib.sha1(content[ap_token_index:ap_token_index + 16].encode()).hexdigest()[10:]
    ap_token_content = f"\"{ap_token_hash}\""

    # Find the location of the definitions to replace them
    ECTF_P_index = content.find("#ifndef __ECTF_PARAMS__")
    comp_ids_index= content.find("#define COMPONENT_IDS")

    with open(output_file, "w") as file:
        # Écrire les définitions de macros avec les nouvelles valeurs
        file.write("#ifndef __ECTF_PARAMS__\n")
        file.write("#define __ECTF_PARAMS__\n")
        file.write(content[:ECTF_P_index])
        file.write("#define AP_PIN {}\n".format(ap_pin_content))
        file.write("#define AP_TOKEN {}\n".format(ap_token_content))
        file.write(content[comp_ids_index:])
        file.close()

 
hash_PIN_TOKEN()
generate_rsa_keys_and_sign()#("save_directory")
command = "mv modified_ectf_params.h inc/ectf_params.h"# ; mv save_directory/public.pem src/public.pem; mv save_directory/signature.bin src/signature.bin"
# Run the command
subprocess.Popen(command, shell=True)



