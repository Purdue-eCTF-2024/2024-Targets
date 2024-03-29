import os
import re
import random
import time
import sys

random.seed(time.time())

directory = sys.argv[1]
direction = sys.argv[2]

comment_pattern = re.compile(r'\s*//\s*ADD_HERE_NOP\s*')  

def add_code_to_file(file_path):
    with open(file_path, 'r') as file:
        code_lines = file.readlines()
    
    comment_line_number = None
    new_code_lines = []
    for i, line in enumerate(code_lines):
        new_code_lines.append(line)
        if comment_pattern.match(line):
            comment_line_number = i
            code_to_add = "__asm(\""+ "   nop\\n" * random.randint(200, 600) + '\");\n'
            new_code_lines.append(code_to_add)
        

    # Check if the comment is found
    if comment_line_number is not None:
        # Add the code line after the comment line       

        # Write the modified code back to the file
        with open(file_path, 'w') as file:
            file.writelines(new_code_lines)
        print(f"Code added after the comment in file: {file_path}")
    else:
        print(f"Comment not found in file: {file_path}")

code_to_add_pattern = re.compile(r'__asm\(\"(?:\s*nop\\n)+\"\)\;')
# re.compile(r'print_debug\(\)\;'
def revert_changes(file_path):
    with open(file_path, 'r') as file:
        code_lines = file.readlines()

    # Find and remove the added code
    modified = False
    new_code_lines = []
    for line in code_lines:
        if code_to_add_pattern.match(line):
            modified = True
        else:
            new_code_lines.append(line)

    # Write the modified code back to the file if changes were made
    if modified:
        with open(file_path, 'w') as file:
            file.writelines(new_code_lines)
        print(f"Changes reverted in file: {file_path}")
    else:
        print(f"No changes found in file: {file_path}")
# flag = int(input("Enter 1 to add code and 0 to revert changes: "))
# Recursively traverse the directory for .c files
for root, dirs, files in os.walk(directory):
    for file in files:
        if file.endswith('.c'):
            file_path = os.path.join(root, file)
            if direction == "add":
                add_code_to_file(file_path)
            else:
                revert_changes(file_path)
