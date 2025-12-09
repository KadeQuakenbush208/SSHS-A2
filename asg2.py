from unicorn import *
from unicorn.arm_const import *
import struct

# Memory Layout
ROM_ADDRESS = 0x00000000
FLASH_ADDRESS = 0x10000000
SRAM_ADDRESS = 0x20000000

# PIN-checking function addresses
START_ADDRESS = 0x1000042c
END_ADDRESS = 0x10000498

# Hook targets 
INPUT_ADDRESS = 0x10008664
SKIP_ADDRESS = 0x100017cc
PUT_ADDRESS = 0x10004d6c
PRINT_ADDRESS = 0x10004e7c

get_flag = False
current_pin = 0 

# Register map 
reg_map = {
    "r0": UC_ARM_REG_R0,
    "r1": UC_ARM_REG_R1,
    "r2": UC_ARM_REG_R2,
    "r3": UC_ARM_REG_R3,
    "r4": UC_ARM_REG_R4,
    "r5": UC_ARM_REG_R5,
    "r6": UC_ARM_REG_R6,
    "r7": UC_ARM_REG_R7,
    "r8": UC_ARM_REG_R8,
    "r9": UC_ARM_REG_R9,
    "r10": UC_ARM_REG_R10,
    "r11": UC_ARM_REG_R11,
    "r12": UC_ARM_REG_R12,
    "sp": UC_ARM_REG_SP,
    "lr": UC_ARM_REG_LR,
    "pc": UC_ARM_REG_PC,
    "xpsr": UC_ARM_REG_XPSR,
    "msp": UC_ARM_REG_MSP,
    "psp": UC_ARM_REG_PSP,
    "primask": UC_ARM_REG_PRIMASK,
    "basepri": UC_ARM_REG_BASEPRI,
    "faultmask": UC_ARM_REG_FAULTMASK,
    "control": UC_ARM_REG_CONTROL
}


# Load files 
def load_file(filename):

    with open(filename, 'rb') as f:
        return f.read()

# Load register
def load_regs(uc):

    try:
        with open("regs.txt", 'r') as f:
            for line in f:
                split = line.split()
                name = split[0].lower()
                reg_addr = int(split[1], 16)
                if name in reg_map:
                    uc.reg_write(reg_map[name], reg_addr)
    except FileNotFoundError:
        print("Couldn't find regs.txt")


# Skip sleep function
def hook_input(uc, address, size, user_data):

    global current_pin
    pin_code = struct.pack("<h", current_pin)

    pin_ptr = uc.reg_read(UC_ARM_REG_R1)
    uc.mem_write(pin_ptr, pin_code)    
    
    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))


# Skip delay/sleep functions
def hook_sleep(uc, address, size, user_data):

    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))


# Hook for printf function to capture output
def hook_print(uc, address, size, user_data):
        
        global get_flag, current_pin
        s = uc.reg_read(UC_ARM_REG_R0)

        try:
            mem_data = uc.mem_read(s, 50)
            output = mem_data.decode('utf-8')

            if "sshs" in output:
                get_flag = True
                print("FLAG FOUND!")
                print(f"Flag Found: {get_flag}")
                print(f"PIN : {current_pin}")
                print(f"FLAG: {output}")
                uc.emu_stop()
        except: 
            pass
       
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))


# Main emulation
def thumb_code():
    
    print("Emulate THUMB code")
    global current_pin

    try:
        # Initialize emulator (Thumb Mode)
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        
        # Map memory 
        mu.mem_map(ROM_ADDRESS, 260 * 1024)
        mu.mem_map(FLASH_ADDRESS, 2 * 1024 * 1024)
        mu.mem_map(SRAM_ADDRESS, 264 * 1024)
        
        # Load file 
        print("Loading binary files.")
        mu.mem_write(ROM_ADDRESS, load_file("rom.bin"))
        mu.mem_write(FLASH_ADDRESS, load_file("fw.bin"))
        mu.mem_write(SRAM_ADDRESS, load_file("sram.bin"))
        print("Binary file loaded.\n")
        
        # Install hooks
        mu.hook_add(UC_HOOK_CODE, hook_input, begin=INPUT_ADDRESS, end=INPUT_ADDRESS)
        mu.hook_add(UC_HOOK_CODE, hook_sleep, begin=PRINT_ADDRESS, end=PRINT_ADDRESS)
        mu.hook_add(UC_HOOK_CODE, hook_sleep, begin=SKIP_ADDRESS, end=SKIP_ADDRESS)
        mu.hook_add(UC_HOOK_CODE, hook_print, begin=PUT_ADDRESS, end=PUT_ADDRESS)
        
        # Loop through all possible PIN
        for pin in range(0, 10000):

            current_pin = pin
            load_regs(mu)
            
            try:
                mu.emu_start(START_ADDRESS | 1, END_ADDRESS) 
            except UcError as e:
                pc = mu.reg_read(UC_ARM_REG_PC)
                print(f"Crash Address (PC): 0x{pc:x}") 
            
            if get_flag:
                break
        
    except Exception as e:
        print("Error: %s" % e)


if __name__ == '__main__':
    thumb_code()

