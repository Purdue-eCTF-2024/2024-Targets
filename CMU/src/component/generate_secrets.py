import sys
sys.path.append('../common/scripts')
sys.path.append('../deployment')

from global_secrets import GlobalSecrets
from crypto_helpers import (
	cc_kdf_ap_boot_sub_key, cc_kdf_att_sub_key, cc_kdf_comp_boot_sub_key, cc_kdf_sec_send_sub_key,
	cc_encrypt_symmetric,
	SYMMETRIC_KEY_LEN, SYMMETRIC_METADATA_LEN)
from parse_header import CParams
import pickle
import monocypher
import json
import pathlib
import os, time
import random
import shutil

def main():
	comp_dir = pathlib.Path(__file__).parent
	root_dir = comp_dir.parent
	build_dir = comp_dir / 'build'
	patch_dir = comp_dir / 'build' / 'patches'

	with open(build_dir / 'params.pickle', 'rb') as f:
		params = pickle.load(f)
	assert(isinstance(params, CParams))

	with open(root_dir / 'deployment' / 'global_secrets.json', 'r') as f:
		g_secrets = GlobalSecrets.from_serialized(json.load(f))

	try:
		shutil.rmtree(patch_dir)
	except FileNotFoundError:
		pass
	os.mkdir(patch_dir)

	# Plaintext AP boot subkey
	ap_boot_subkey = cc_kdf_ap_boot_sub_key(g_secrets.ap_boot_root_key, params.c_id)

	# Component attestation data encrypted with the attestation subkey
	att_subkey = cc_kdf_att_sub_key(g_secrets.att_root_key, params.c_id)
	att_plaintext = params.attestation_bytes()
	encrypted_att_data = cc_encrypt_symmetric(att_plaintext, att_subkey)

	# Deployment key for secure link layer
	deployment_key = g_secrets.deployment_key

	# Key used to resist catastrophic nonce reuse during AEAD
	nonce_key = monocypher.generate_key()

	# Component ID
	resources = (
		params.c_id.to_bytes(4, 'little') +
		ap_boot_subkey +
		encrypted_att_data +
		deployment_key +
		nonce_key
	)

	with open(patch_dir / 'resources.bin', 'wb') as f:
		f.write(resources)


	# Boot metadata blob encrypted with component boot subkey

	c_boot_subkey = cc_kdf_comp_boot_sub_key(g_secrets.c_boot_root_key, params.c_id)

	secure_send_subkey = cc_kdf_sec_send_sub_key(g_secrets.secure_send_root_key, (params.c_id & 0x7F))
	
	c_code_key = monocypher.generate_key()

	boot_metadata_plaintext = (
		c_code_key +
		secure_send_subkey +
		params.boot_message_bytes()
	)

	encrypted_boot_metadata = cc_encrypt_symmetric(boot_metadata_plaintext, c_boot_subkey)

	with open(patch_dir / 'boot-blob-page.bin', 'wb') as f:
		f.write(encrypted_boot_metadata)


	# POST_BOOT_CODE encrypted with K_ccode

	with open(build_dir / 'plaintext-code.bin', 'rb') as f:
		plaintext_code = f.read()

	assert(all(b == 0 for b in plaintext_code[-40:]))

	encrypted_code = cc_encrypt_symmetric(plaintext_code[:-40], c_code_key)

	with open(patch_dir / 'encrypted-code.bin', 'wb') as f:
		f.write(encrypted_code)

	# 8192 bytes of seed entropy
	with open(patch_dir / 'entropy.bin', 'wb') as f:
		f.write(random.randbytes(8192))

	# defense lockout canary
	with open(patch_dir / 'defense-lockout.bin', 'wb') as f:
		f.write(b"\x00\x00\x00\x00")
		f.write(b"\xFF" * (8192 - 4))

if __name__ == '__main__':
	main()
