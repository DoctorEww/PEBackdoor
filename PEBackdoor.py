import pefile
import functools

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

def interactive():
    pe_path = "../putty.exe"

    pe = pefile.PE(pe_path)

    original_start = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print(original_start)
    pe.close()
    #pe.write("puddy.exe")
    caves = code_caves(150, pe_path)
    print(caves)
    caves[1].print_cave()




if __name__ == "__main__":
    interactive()
    print("done!")