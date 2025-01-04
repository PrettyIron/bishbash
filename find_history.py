import os
import struct
import sys

HISTORY_LIST_OFFSET = 0xfa8a0

def get_base_address(pid):
    """Get the base address of a process from /proc/[pid]/maps"""
    try:
        with open(f"/proc/{pid}/maps", "r") as f:
            # First line contains the base mapping
            first_line = f.readline()
            # Extract the start address (in hex)
            base_addr = int(first_line.split('-')[0], 16)
            return base_addr
    except PermissionError:
        print("Error: Permission denied. Try running with sudo.")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: Process {pid} not found.")
        sys.exit(1)

def read_process_memory(pid, addr, size):
    """Read 'size' bytes from process memory at 'addr'"""
    try:
        with open(f"/proc/{pid}/mem", "rb") as f:
            # Seek to the desired address
            f.seek(addr)
            # Read the specified number of bytes
            data = f.read(size)
            return data
    except PermissionError:
        print("Error: Permission denied. Try running with sudo.")
        sys.exit(1)
    except (IOError, OSError) as e:
        print(f"Error reading process memory: {e}")
        sys.exit(1)

def read_integer(pid, addr):
    """Read a 4-byte integer from the specified address"""
    try:
        data = read_process_memory(pid, addr, 4)
        # Unpack as a little-endian 32-bit integer
        return struct.unpack("<i", data)[0]
    except struct.error as e:
        print(f"Error unpacking integer: {e}")
        sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pid>")
        sys.exit(1)
    
    pid = int(sys.argv[1])
    
    # Get base address
    base_addr = get_base_address(pid)
    print(f"Base address: 0x{base_addr:x}")
    
    target_addr = base_addr + HISTORY_LIST_OFFSET
    print(f"Target address: 0x{target_addr:x}")
    
    offset = read_integer(pid,target_addr + 7)
    print(f"Offset: 0x{offset:x}")
    
    the_history_addr = target_addr + 11 + offset
    print(f"the_history Address: 0x{the_history_addr:x}")

if __name__ == "__main__":
    main()