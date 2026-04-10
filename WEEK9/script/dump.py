import idaapi
import idc
import idautils
def dump_memory_region_debugger(start_address, size, output_file="dumped_memory_debugger.bin"):
  if not idaapi.is_debugger_on():
    print("Error: Debugger is not active. Please launch or attach to a process first.")
    return
  print(f"Attempting to dump memory via debugger from address: 0x{start_address:X} with size: 0x{size:X}")
  try:
    dumped_data = idaapi.dbg_read_memory(start_address, size)
    if dumped_data is None:
      print(f"Error: Could not read bytes from 0x{start_address:X} with size 0x{size:X} using dbg_read_memory. The region might be unmapped or inaccessible to the debugger.")
      return
    with open(output_file, "wb") as f:
      f.write(dumped_data)
    print(f"Successfully dumped 0x{len(dumped_data):X} bytes from 0x{start_address:X} to '{output_file}' using debugger API.")
  except Exception as e:
    print(f"An error occurred during debugger memory read: {e}")

if __name__ == '__main__':
    start_addr_int = 0x1E2A4099610
    dump_size_int = 0x1CC50
    output_filename = "debug_dump_via_debugger.bin"
    dump_memory_region_debugger(start_addr_int, dump_size_int, output_filename)