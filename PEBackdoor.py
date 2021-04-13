#!/usr/bin/python3
import pefile
import functools
import argparse

@functools.total_ordering
class code_cave:
    def __init__(self, location, size, section):
        self.location = location
        self.size = size
        self.section = section
        self.section_name = section.Name
    
    def __lt__(self, other):
        return (self.size) < (other.size)

    def __eq__(self, other):
        return (self.size) == (other.size)

    def print_cave(self):
        print(f"Code cave at {hex(self.location)} of size {self.size} in {self.section_name.decode()}")

def code_caves(min_size, pe_path):
    """
    This function takes in a pe file, a minimum codecave size, and the path to the pe file.

    """
    pe = pefile.PE(pe_path)
    print("Searching for code caves")
    caves = []

    fd = open(pe_path, "rb")
    for section in pe.sections:
        if section.SizeOfRawData < min_size: #Skip sections too small
            continue
        fd.seek(section.PointerToRawData, 0) 
        data = fd.read(section.SizeOfRawData)
        
        cave_size = 0
        pos = 0
        for byte in data:
            if byte == 0x00:
                cave_size += 1
            else:
                if cave_size > min_size:
                    cave_location = section.PointerToRawData + pos - cave_size 
                    caves.append(code_cave(location=cave_location, size=cave_size, section=section))

                cave_size = 0
            pos += 1
    caves.sort(reverse=True)
    return caves

def interactive(pe_path):
    #pe_path = "../putty.exe"

    pe = pefile.PE(pe_path)

    original_start = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print(original_start)
    pe.close()
    #pe.write("puddy.exe")
    caves = code_caves(150, pe_path)
    print(caves)

def PEBackdoor():
    print("main")



if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Inject shell code into code caves automatically")

    parser.add_argument("-f", "--file", dest="file_name", action="store", required=True,
                        help="PE file", type=str)

    parser.add_argument("-s", "--shell", dest="shell_code", action="store", default=" ",
                        help="shell code", type=str)

    parser.add_argument("-o", "--out", dest="output", action="store", default="out.exe",
                        help="output file", type=str)
    args = parser.parse_args()
    interactive(args.file_name)
    print("done!")