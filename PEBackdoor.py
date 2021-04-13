import pefile

exe_path = "putty.exe"

pe = pefile.PE(exe_path)

original_start = pe.OPTIONAL_HEADER.AddressOfEntryPoint

#pe.write("puddy.exe")
