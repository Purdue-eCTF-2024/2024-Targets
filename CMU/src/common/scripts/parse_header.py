import sys
import pickle
from typing import Dict, Any
from dataclasses import dataclass

AP_BOOT_MSG_LEN = 64

C_BOOT_MSG_LEN = 64

ATTEST_INFO_LEN = 64


@dataclass
class APParams:
	pin: str
	token: str
	ids: list[int]
	boot_msg: bytes

	def pin_bytes(self):
		return self.pin.encode('ascii')

	def token_bytes(self):
		return self.token.encode('ascii')

def parse_ap_header(contents: str) -> APParams:
	lines = contents.splitlines()

	#ifndef __ECTF_PARAMS__
	#define __ECTF_PARAMS__
	#define AP_PIN "123456"
	#define AP_TOKEN "0123456789abcdef"
	#define COMPONENT_IDS 0x11111124, 0x11111150
	#define COMPONENT_CNT 2
	#define AP_BOOT_MSG "Test boot message"
	#endif

	assert(lines[0] == '#ifndef __ECTF_PARAMS__')
	assert(lines[1] == '#define __ECTF_PARAMS__')
	ap_pin = parse_c_str(try_remove_prefix(lines[2], "#define AP_PIN "))
	ap_token = parse_c_str(try_remove_prefix(lines[3], "#define AP_TOKEN "))
	component_ids = parse_comma_list(try_remove_prefix(lines[4], "#define COMPONENT_IDS "))
	component_cnt = parse_int(try_remove_prefix(lines[5], "#define COMPONENT_CNT "))
	ap_boot_msg = parse_c_str(try_remove_prefix(lines[6], "#define AP_BOOT_MSG "))
	assert(lines[7] == "#endif")
	assert(len(lines) == 8)

	ap_boot_msg = ap_boot_msg.encode('ascii')
	ap_boot_msg += b'\0' * (AP_BOOT_MSG_LEN - len(ap_boot_msg))
	assert(len(ap_boot_msg) == AP_BOOT_MSG_LEN)
	
	assert(len(component_ids) == component_cnt)

	return APParams(ap_pin, ap_token, component_ids, ap_boot_msg)

@dataclass
class CParams:
	c_id: int
	boot_msg: str
	att_location: str
	att_date: str
	att_customer: str

	def attestation_bytes(self):
		att_location = self.att_location.encode('ascii')
		att_date     = self.att_date.encode('ascii')
		att_customer = self.att_customer.encode('ascii')

		# Ensure there's no extraneous nulls inside the strings
		assert(b'\0' not in att_location)
		assert(b'\0' not in att_date)
		assert(b'\0' not in att_customer)

		# Ensure there is space for a null terminator
		assert(len(att_location) <= ATTEST_INFO_LEN)
		assert(len(att_date)     <= ATTEST_INFO_LEN)
		assert(len(att_customer) <= ATTEST_INFO_LEN)

		b = (
			(att_location + b'\0' * (ATTEST_INFO_LEN))[:ATTEST_INFO_LEN] +
			(att_date     + b'\0' * (ATTEST_INFO_LEN))[:ATTEST_INFO_LEN] +
			(att_customer + b'\0' * (ATTEST_INFO_LEN))[:ATTEST_INFO_LEN])

		return b
	
	def boot_message_bytes(self):
		return (self.boot_msg.encode('ascii') + b'\0' * C_BOOT_MSG_LEN)[:C_BOOT_MSG_LEN]

def parse_component_header(contents: str) -> CParams:
	lines = contents.splitlines()

	#ifndef __ECTF_PARAMS__
	#define __ECTF_PARAMS__
	#define COMPONENT_ID 0x11111125
	#define COMPONENT_BOOT_MSG "Component boot"
	#define ATTESTATION_LOC "McLean"
	#define ATTESTATION_DATE "08/08/08"
	#define ATTESTATION_CUSTOMER "Fritz"
	#endif

	assert(lines[0] == '#ifndef __ECTF_PARAMS__')
	assert(lines[1] == '#define __ECTF_PARAMS__')
	c_id = parse_int(try_remove_prefix(lines[2], "#define COMPONENT_ID "))
	boot_msg = parse_c_str(try_remove_prefix(lines[3], "#define COMPONENT_BOOT_MSG "))
	att_location = parse_c_str(try_remove_prefix(lines[4], "#define ATTESTATION_LOC "))
	att_date = parse_c_str(try_remove_prefix(lines[5], "#define ATTESTATION_DATE "))
	att_customer = parse_c_str(try_remove_prefix(lines[6], "#define ATTESTATION_CUSTOMER "))
	assert(lines[7] == "#endif")
	assert(len(lines) == 8)

	return CParams(c_id, boot_msg, att_location, att_date, att_customer)


def parse_c_str(s: str):
	assert(s.startswith('"'))
	assert(s.endswith('"'))
	s = s[1:-1]

	assert('"' not in s)
	assert('\\' not in s)

	return s

def parse_comma_list(s: str):
	return [parse_int(item) for item in s.split(',')]

def parse_int(s: str):
	return int(s.strip(), base=0)

def try_remove_prefix(s: str, prefix: str):
	if not s.startswith(prefix):
		raise Exception()
	return s.removeprefix(prefix)

def main():
	assert(len(sys.argv) == 4)

	with open(sys.argv[2], 'r') as f:
		contents = f.read()

	if sys.argv[1] == 'ap':
		params = parse_ap_header(contents)
		print(f'-DCOMPONENT_CNT={len(params.ids)}', end='')
	elif sys.argv[1] == 'comp':
		params = parse_component_header(contents)
	else:
		raise Exception(sys.argv[1])
	
	with open(sys.argv[3], 'wb') as f:
		pickle.dump(params, f)
	
if __name__ == '__main__':
	main()
