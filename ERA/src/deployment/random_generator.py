import random
import string

def get_random_string():
    # Generate secrets and salts randomly
    letters = string.ascii_letters + string.digits
    words = [''.join(random.choice(letters) for j in range(random.randint(1,3))) for i in range(6)]
    dots = [''.join("." for j in range(i)) for i in range(1,5)]
    result_str = ''.join(dots[random.randint(0,3)] + words[i] for i in range(6))
    return result_str
#storing secrets in global secrets 
secret_file=open("global_secrets.h",'w')
secret_list=[get_random_string() for i in range(8)]
secret_file.write("#define AP_secret_id \""+secret_list[0]+"\"\n"+"#define COMP_secret_id \""+secret_list[1]+"\"\n"+"#define SECRET_messaging \""+secret_list[2]+"\"\n"+"#define PIN_salt \""+secret_list[3]+"\"\n"+"#define TOKEN_salt \""+secret_list[4]+"\"\n"+"#define KEY \""+secret_list[5]+"\"\n"+"#define COMP_KEY \""+secret_list[6]+"\"\n"+"#define AP_KEY \""+secret_list[7]+"\"\n")
secret_file.close()
