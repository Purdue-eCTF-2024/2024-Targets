import monocypher
import json
import pathlib
import base64
import sys
from dataclasses import dataclass

def to_base64(bytes):
	return base64.b64encode(bytes).decode('ascii')

def from_base64(s: str):
	return base64.b64decode(s)

@dataclass
class GlobalSecrets:
	ap_boot_root_key: bytes
	c_boot_root_key: bytes
	att_root_key: bytes
	secure_send_root_key: bytes
	deployment_key: bytes

	@classmethod
	def generate(cls):
		ap_boot_root_key = monocypher.generate_key()
		c_boot_root_key = monocypher.generate_key()
		att_root_key = monocypher.generate_key()
		secure_send_root_key = monocypher.generate_key()
		deployment_key = monocypher.generate_key()

		return cls(ap_boot_root_key, c_boot_root_key, att_root_key, secure_send_root_key, deployment_key)

	def to_serialized(self):
		secrets = dict()
		secrets['AP_BOOT_ROOT_KEY']     = to_base64(self.ap_boot_root_key)
		secrets['C_BOOT_ROOT_KEY']      = to_base64(self.c_boot_root_key)
		secrets['ATT_ROOT_KEY_ENCRYPTED']         = to_base64(self.att_root_key)
		secrets['SECURE_SEND_ROOT_KEY'] = to_base64(self.secure_send_root_key)
		secrets['DEPLOYMENT_KEY'] = to_base64(self.deployment_key)
		return secrets

	@classmethod
	def from_serialized(cls, ser):
		ap_boot_root_key = from_base64(ser['AP_BOOT_ROOT_KEY'])
		c_boot_root_key = from_base64(ser['C_BOOT_ROOT_KEY'])
		att_root_key = from_base64(ser['ATT_ROOT_KEY_ENCRYPTED'])
		secure_send_root_key = from_base64(ser['SECURE_SEND_ROOT_KEY'])
		deployment_key = from_base64(ser['DEPLOYMENT_KEY'])

		assert(len(ap_boot_root_key) == 32)
		assert(len(c_boot_root_key) == 32)
		assert(len(att_root_key) == 32)
		assert(len(secure_send_root_key) == 32)
		assert(len(deployment_key) == 32)

		return cls(ap_boot_root_key, c_boot_root_key, att_root_key, secure_send_root_key, deployment_key)

def main():
	secrets = GlobalSecrets.generate()

	with open('global_secrets.json', 'w') as f:
		json.dump(secrets.to_serialized(), f)

if __name__ == '__main__':
	main()
