from ecdsa import SigningKey, SECP256k1, util  # pip install ecdsa and import required libraries: SigningKey, SECP256k1, util
import os
import hashlib

AP_x_coord = ""
AP_y_coord = ""

rng = util.PRNG(os.urandom(256))
private_key = SigningKey.generate(curve=SECP256k1, entropy=rng, hashfunc=hashlib.sha256)
public_key = private_key.verifying_key

f1 = open("AP_Keys.h", "w")
f1.write("#define AP_Private_Key " + '"' + private_key.to_string().hex() + '"' + "\n")

AP_x = public_key.pubkey.point.x()
AP_y = public_key.pubkey.point.y()

AP_x_coord = hex(AP_x)[2:]
AP_x_coord_len = len(AP_x_coord)
if(AP_x_coord_len<64) :
    pad_len = 64- AP_x_coord_len
    AP_x_coord = '0'*pad_len + AP_x_coord

AP_y_coord = hex(AP_y)[2:]
AP_y_coord_len = len(AP_y_coord)
if(AP_y_coord_len<64) :
    pad_len = 64- AP_y_coord_len
    AP_y_coord = '0'*pad_len + AP_y_coord

#for i in range(1, 3):
rng = util.PRNG(os.urandom(256))
private_key = SigningKey.generate(curve=SECP256k1, entropy=rng, hashfunc=hashlib.sha256)
public_key = private_key.verifying_key

f2 = open("Comp_Keys.h", "w")
f2.write("#define Comp_Private_Key " + '"' + private_key.to_string().hex() + '"' + "\n")

Client_x = public_key.pubkey.point.x()
Client_y = public_key.pubkey.point.y()

Client_x_coord = hex(Client_x)[2:]
Client_x_coord_len = len(Client_x_coord)
if(Client_x_coord_len<64) :
    pad_len = 64- Client_x_coord_len
    Client_x_coord = '0'*pad_len + Client_x_coord

Client_y_coord = hex(Client_y)[2:]
Client_y_coord_len = len(Client_y_coord)
if(Client_y_coord_len<64) :
    pad_len = 64- Client_y_coord_len
    Client_y_coord = '0'*pad_len + Client_y_coord

f2.write(f'#define AP_X "{AP_x_coord}"\n')
f2.write(f'#define AP_Y "{AP_y_coord}"\n')
f2.close()
f1.write(f'#define Comp_X "{Client_x_coord}"\n')
f1.write(f'#define Comp_Y "{Client_y_coord}"\n')
f1.close()