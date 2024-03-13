import sys
from dataclasses import dataclass
import random

BASE_ADDR = 0x1000_E000
PAGE_SIZE = 0x2000

CODE_SIZE = 0x0003_0000

FLASH_SIZE = 0x0003_8000

@dataclass
class AddrRange:
	base: int
	size: int

	def __init__(self, base: int, size: int):
		assert(base % PAGE_SIZE == 0)
		assert(size % PAGE_SIZE == 0)
		self.base = base
		self.size = size

	def overlaps(self, other: 'AddrRange') -> bool:
		start = max(self.base, other.base)
		end   = min(self.end(), other.end())
		return start < end
	
	def end(self) -> int:
		return self.base + self.size


def addr_to_offset(addr: int) -> int:
	return addr - BASE_ADDR

def read_bin(path: str) -> bytes:
	with open(path, 'rb') as f:
		data = f.read()
	
	padding_len = (PAGE_SIZE - (len(data) % PAGE_SIZE)) % PAGE_SIZE;

	data = data + padding_len * b'\xEA'

	return data

def generate_padding(size):
	random.seed(42)

	result = b''
	
	padding = [b'ectf{lol}', b'ectf{lmao}', b'ectf{42}', b'ectf{flag_fake}', b'ectf{owo}', b'ectf{uwu}', b'ectf{:3}']

	while len(result) < size:
		result += random.choice(padding)
	
	return result[:size]

def overwrite(original: bytes, new: bytes, addr: int):
	start = addr_to_offset(addr)
	end = addr_to_offset(addr) + len(new)

	written = original[:start] + new + original[end:]

	assert(len(written) == len(original))

	return written

def main():
	inpath = sys.argv[1]
	outpath = sys.argv[2]

	patches = [pair.split(',') for pair in sys.argv[3:]]
	patches = [(read_bin(path), int(addr, 0)) for path, addr in patches]

	with open(inpath, 'rb') as f:
		prog_data = f.read()

	while len(prog_data) < CODE_SIZE:
		prog_data = prog_data + b'bnyahaj :3c '

	prog_data = prog_data[:CODE_SIZE]
	assert(len(prog_data) == CODE_SIZE)

	prog_range = AddrRange(BASE_ADDR, len(prog_data))

	ranges = [prog_range] + [AddrRange(addr, len(data)) for data, addr in patches]
	for i in range(0, len(ranges)):
		for j in range(i + 1, len(ranges)):
			if ranges[i].overlaps(ranges[j]):
				raise Exception(f'overlapping ranges {ranges[i]}, {ranges[j]}')

	outdata = generate_padding(FLASH_SIZE)

	outdata = overwrite(outdata, prog_data, BASE_ADDR)
	for patch_data, patch_addr in patches:
		outdata = overwrite(outdata, patch_data, patch_addr)
	
	with open(outpath, 'wb') as f:
		f.write(outdata)

if __name__ == '__main__':
	main()
