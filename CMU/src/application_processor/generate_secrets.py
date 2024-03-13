import sys
sys.path.append('../common/scripts')
sys.path.append('../deployment')

from global_secrets import GlobalSecrets
from crypto_helpers import (
	cc_kdf_ap_boot_sub_key, cc_kdf_pin, cc_kdf_rt,
	cc_encrypt_symmetric,
	SYMMETRIC_KEY_LEN, SYMMETRIC_METADATA_LEN)
from parse_header import AP_BOOT_MSG_LEN, APParams
import pickle
import monocypher
import json
import pathlib
import os
import random
import shutil

def main():
	ap_dir = pathlib.Path(__file__).parent
	root_dir = ap_dir.parent
	build_dir = ap_dir / 'build'
	patch_dir = ap_dir / 'build' / 'patches'

	with open(build_dir / 'params.pickle', 'rb') as f:
		params = pickle.load(f)
	assert(isinstance(params, APParams))

	with open(root_dir / 'deployment' / 'global_secrets.json', 'r') as f:
		g_secrets = GlobalSecrets.from_serialized(json.load(f))

	try:
		shutil.rmtree(patch_dir)
	except FileNotFoundError:
		pass
	os.mkdir(patch_dir)
	
	sorted_ids = sorted(params.ids)

	replacement_token = params.token_bytes()

	# Boot Metadata, encrypted with AP boot subkeys in ascending order

	ap_code_key = monocypher.generate_key()

	boot_metadata_plaintext = (
		g_secrets.c_boot_root_key +
		g_secrets.secure_send_root_key +
		ap_code_key +
		params.boot_msg
	)

	assert(len(boot_metadata_plaintext) == 3 * SYMMETRIC_KEY_LEN + AP_BOOT_MSG_LEN)

	encrypted_boot_metadata = boot_metadata_plaintext
	for c_id in sorted_ids:
		ap_boot_subkey = cc_kdf_ap_boot_sub_key(g_secrets.ap_boot_root_key, c_id)

		encrypted_boot_metadata = cc_encrypt_symmetric(encrypted_boot_metadata, ap_boot_subkey)

	assert(len(encrypted_boot_metadata) == len(boot_metadata_plaintext) + len(sorted_ids) * SYMMETRIC_METADATA_LEN)

	boot_blob_page = b''
	for c_id in sorted(params.ids):
		boot_blob_page += c_id.to_bytes(4, 'little')
	boot_blob_page += encrypted_boot_metadata

	with open(patch_dir / 'boot-blob-page.bin', 'wb') as f:
		f.write(boot_blob_page)

	# Post boot code encrypted with K_apcode

	with open(build_dir / 'plaintext-code.bin', 'rb') as f:
		plaintext_code = f.read()

	assert(all(b == 0 for b in plaintext_code[-40:]))

	encrypted_code = cc_encrypt_symmetric(plaintext_code[:-40], ap_code_key)

	with open(patch_dir / 'encrypted-code.bin', 'wb') as f:
		f.write(encrypted_code)

	# 8192 bytes of seed entropy
	with open(patch_dir / 'entropy.bin', 'wb') as f:
		f.write(random.randbytes(8192))

	# defense lockout canary
	with open(patch_dir / 'defense-lockout.bin', 'wb') as f:
		f.write(b"\x00\x00\x00\x00")
		f.write(b"\xFF" * (8192 - 4))

	# Attestation root key encrypted with KDF(PIN)
	pin_key = cc_kdf_pin(params.pin_bytes(), g_secrets.deployment_key)
	encrypted_att_root_key = cc_encrypt_symmetric(g_secrets.att_root_key, pin_key)
	assert(len(encrypted_att_root_key) == SYMMETRIC_METADATA_LEN + SYMMETRIC_KEY_LEN)

	# AP Boot Root Key, encrypted with the KDF of the replacement token
	replacement_token_key = cc_kdf_rt(replacement_token, g_secrets.deployment_key)
	encrypted_ap_boot_root_key = cc_encrypt_symmetric(g_secrets.ap_boot_root_key, replacement_token_key)
	assert(len(encrypted_ap_boot_root_key) == SYMMETRIC_METADATA_LEN + SYMMETRIC_KEY_LEN)

	# Deployment key for secure link layer
	deployment_key = g_secrets.deployment_key

	# Key used to resist catastrophic nonce reuse during AEAD
	nonce_key = monocypher.generate_key()

	keys = encrypted_att_root_key + encrypted_ap_boot_root_key + deployment_key + nonce_key
	with open(patch_dir / 'keys.bin', 'wb') as f:
		f.write(keys)

if __name__ == '__main__':
	main()
