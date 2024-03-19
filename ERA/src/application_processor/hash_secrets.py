from Crypto.Hash import *
from pathlib import Path
import time
file_param = open(Path("inc/ectf_params.h"), "r")
file_global = open(Path("../deployment/global_secrets.h"), "r")
txt=file_param.readlines()
text=file_global.readlines()
file_global.close()
file_param.close()
n=len(text[3])
PIN_salt=text[3][18:n-2]
n=len(text[4])
TOKEN_salt=text[4][20:n-2]
n=len(txt[2])
AP_PIN=txt[2][16:n-2]
AP_PIN+=PIN_salt
n=len(txt[3])
AP_TOKEN=txt[3][18:n-2]
AP_TOKEN+=TOKEN_salt
secret_hashs=[]
secrets_list=[AP_PIN,AP_TOKEN]
for x in secrets_list:
	x_hash= SHA256.new()
	x_hash.update(x.encode())
	secret_hashs+=[x_hash.hexdigest()]
file_param = open(Path("inc/ectf_params.h"), "w")
file_param.write(txt[0])
file_param.write(txt[1])
file_param.write("#define AP_PIN \""+secret_hashs[0]+"\"\n"+"#define AP_TOKEN \""+secret_hashs[1]+"\"\n")
file_param.write(txt[4])
file_param.write(txt[5])
file_param.write(txt[6])
file_param.write(txt[7])
file_param.close()
