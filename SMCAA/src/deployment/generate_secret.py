import random
import sys

nums = []
for x in range(16):
    n = random.randint(0, 255)
    nums.append(hex(n))

hex_str = ", ".join(nums)

print("uint8_t SECRET[] = { " + hex_str + " };", file=sys.stdout)