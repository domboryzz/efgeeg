import ctypes
import ctypes.wintypes as wintypes

class SelectiveByteCleaner:
    def __init__(self):
        if ctypes.sizeof(ctypes.c_voidp) == 8:
            self.is_64bit = True
        else:
            self.is_64bit = False
    
    def clean_specific_bytes(self, addresses):
        try:
            kernel32 = ctypes.windll.kernel32
            
            process_handle = kernel32.GetCurrentProcess()
            
            for address in addresses:
                try:
                    if isinstance(address, str):
                        addr = int(address, 16)
                    else:
                        addr = address
                    
                    ptr = ctypes.cast(addr, ctypes.POINTER(ctypes.c_ubyte))
                    ptr.contents = ctypes.c_ubyte(0)
                    
                except:
                    continue
                    
            return True
            
        except:
            return False
    
    def clean_byte_pattern(self, start_addr, pattern_bytes):
        try:
            if isinstance(start_addr, str):
                addr = int(start_addr, 16)
            else:
                addr = start_addr
            
            for i, byte_val in enumerate(pattern_bytes):
                try:
                    ptr = ctypes.cast(addr + i, ctypes.POINTER(ctypes.c_ubyte))
                    ptr.contents = ctypes.c_ubyte(0)
                except:
                    continue
                    
            return True
        except:
            return False

def clean_bytes(*addresses):
    cleaner = SelectiveByteCleaner()
    return cleaner.clean_specific_bytes(addresses)

def clean_pattern(start_address, byte_count=4):
    cleaner = SelectiveByteCleaner()
    pattern = [0] * byte_count
    return cleaner.clean_byte_pattern(start_address, pattern)

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04

if __name__ == "__main__":
    clean_bytes(MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE)
