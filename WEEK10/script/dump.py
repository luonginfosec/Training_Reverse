import idc
import os

esi_address = idc.get_reg_value("esi")
string_bytes = idc.get_strlit_contents(esi_address, -1, idc.STRTYPE_C)

if string_bytes:
    decoded_string = string_bytes.decode('utf-8', errors='ignore')
    dump_path = r"dump.txt"
    with open(dump_path, "w") as f:
        f.write(decoded_string)
    print("ok")   
else:
    print("error")