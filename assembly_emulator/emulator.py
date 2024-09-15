import sys
import logging
from unicorn import *
from unicorn.x86_const import *
from keystone import *

class AssemblyEmulator:
    def __init__(self, arch=UC_ARCH_X86, mode=UC_MODE_64, log_level=logging.INFO):
        """
        Initialize the AssemblyEmulator with specified architecture, mode, and logging level.

        Args:
            arch (int): Unicorn architecture constant.
            mode (int): Unicorn mode constant.
            log_level (int): Logging level from the logging module.
        """
        self.arch = arch
        self.mode = mode
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)  # Default to x86_64
        self.mu = Uc(self.arch, self.mode)
        self.memory_map = {}
        self.registers = {}
        self.code = b''
        self.address = 0x1000000  # Default starting address
        self.stack_address = 0x0  # Default stack address (can be set)
        self.stack_size = 2 * 1024 * 1024  # 2MB stack
        self.hooked = False

        # Set up logging
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(log_level)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def assemble(self, assembly_code):
        """
        Assemble the given assembly code into machine code.

        Args:
            assembly_code (str): The assembly code as a string.

        Returns:
            bytes: The assembled machine code.
        """
        try:
            encoding, count = self.ks.asm(assembly_code)
            self.code = bytes(encoding)
            self.logger.debug(f"Assembly successful: {count} instructions assembled.")
            self.logger.debug(f"Machine code: {self.code.hex()}")
            return self.code
        except KsError as e:
            self.logger.error(f"Keystone assembly error: {e}")
            sys.exit(1)

    def map_memory(self, address=0x1000000, size=2 * 1024 * 1024):
        """
        Map memory for the emulator.

        Args:
            address (int): Starting address for code memory.
            size (int): Size of the memory to map.
        """
        self.address = address
        try:
            self.mu.mem_map(address, size)
            self.memory_map[address] = size
            self.logger.debug(f"Memory mapped at {hex(address)} with size {size} bytes.")
        except UcError as e:
            self.logger.error(f"Unicorn memory mapping error: {e}")
            sys.exit(1)

    def load_code(self, code, address=None):
        """
        Load machine code into the emulator's memory.

        Args:
            code (bytes): Machine code to load.
            address (int, optional): Address to load the code. Defaults to self.address.
        """
        if address is None:
            address = self.address
        try:
            self.mu.mem_write(address, code)
            self.code = code
            self.logger.debug(f"Loaded code at {hex(address)}: {code.hex()}")
        except UcError as e:
            self.logger.error(f"Unicorn memory write error: {e}")
            sys.exit(1)

    def set_registers(self, **kwargs):
        """
        Set initial register values.

        Args:
            **kwargs: Register names and their values. Example: rax=0, rdx=10
        """
        reg_map = {
            'rax': UC_X86_REG_RAX,
            'rbx': UC_X86_REG_RBX,
            'rcx': UC_X86_REG_RCX,
            'rdx': UC_X86_REG_RDX,
            'rsi': UC_X86_REG_RSI,
            'rdi': UC_X86_REG_RDI,
            'rsp': UC_X86_REG_RSP,
            'rbp': UC_X86_REG_RBP,
            'r8': UC_X86_REG_R8,
            'r9': UC_X86_REG_R9,
            'r10': UC_X86_REG_R10,
            'r11': UC_X86_REG_R11,
            'r12': UC_X86_REG_R12,
            'r13': UC_X86_REG_R13,
            'r14': UC_X86_REG_R14,
            'r15': UC_X86_REG_R15,
            'rip': UC_X86_REG_RIP,
            # Add more registers if needed
        }

        for reg, value in kwargs.items():
            reg_lower = reg.lower()
            if reg_lower in reg_map:
                try:
                    self.mu.reg_write(reg_map[reg_lower], value)
                    self.registers[reg_lower] = value
                    self.logger.debug(f"Register {reg_lower.upper()} set to {value}.")
                except UcError as e:
                    self.logger.error(f"Error setting register {reg_lower}: {e}")
                    sys.exit(1)
            else:
                self.logger.error(f"Unknown register: {reg}")
                sys.exit(1)

    def hook_code(self, uc, address, size, user_data):
        """
        Hook to log each executed instruction.

        Args:
            uc (Uc): The Unicorn emulator instance.
            address (int): Current instruction address.
            size (int): Size of the instruction.
            user_data: User data (unused).
        """
        # Read the instruction bytes
        try:
            code = self.mu.mem_read(address, size)
            mnemonic = self.disassemble(code, address)
            self.logger.info(f"Executing instruction at {hex(address)}: {mnemonic}")
            # Optionally, log register states
            regs = self.get_registers()
            reg_states = ', '.join([f"{k.upper()}={v}" for k, v in regs.items()])
            self.logger.debug(f"Register States: {reg_states}")
        except UcError as e:
            self.logger.error(f"Error in hook_code: {e}")

    def disassemble(self, code, address):
        """
        Disassemble the given machine code.

        Args:
            code (bytes): Machine code bytes.
            address (int): Address of the instruction.

        Returns:
            str: Disassembled instruction as a string.
        """
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        except ImportError:
            self.logger.error("Capstone module not installed. Install it via `pip install capstone`.")
            sys.exit(1)

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for insn in md.disasm(code, address):
            return f"{insn.mnemonic} {insn.op_str}"
        return "Unknown Instruction"

    def run(self, start_address=None, end_address=None, timeout=10, debug=False):
        """
        Run the emulation.

        Args:
            start_address (int, optional): Start address for emulation.
            end_address (int, optional): End address for emulation.
            timeout (int, optional): Timeout in seconds for emulation.
            debug (bool, optional): Enable detailed debugging logs.
        """
        if start_address is None:
            start_address = self.address
        if end_address is None:
            end_address = self.address + len(self.code)

        # Add a code hook to log instructions
        if not self.hooked:
            self.mu.hook_add(UC_HOOK_CODE, self.hook_code)
            self.hooked = True

        try:
            self.logger.info(f"Starting emulation from {hex(start_address)} to {hex(end_address)}.")
            self.mu.emu_start(start_address, end_address, timeout=timeout, timeout_usec=0)
            self.logger.info("Emulation finished successfully.")
        except UcError as e:
            self.logger.error(f"Unicorn emulation error: {e}")
            sys.exit(1)

    def get_registers(self):
        """
        Retrieve the current state of all general-purpose registers.

        Returns:
            dict: A dictionary of register names and their current values.
        """
        reg_map = {
            'rax': UC_X86_REG_RAX,
            'rbx': UC_X86_REG_RBX,
            'rcx': UC_X86_REG_RCX,
            'rdx': UC_X86_REG_RDX,
            'rsi': UC_X86_REG_RSI,
            'rdi': UC_X86_REG_RDI,
            'rsp': UC_X86_REG_RSP,
            'rbp': UC_X86_REG_RBP,
            'r8': UC_X86_REG_R8,
            'r9': UC_X86_REG_R9,
            'r10': UC_X86_REG_R10,
            'r11': UC_X86_REG_R11,
            'r12': UC_X86_REG_R12,
            'r13': UC_X86_REG_R13,
            'r14': UC_X86_REG_R14,
            'r15': UC_X86_REG_R15,
            'rip': UC_X86_REG_RIP,
            # Add more registers if needed
        }

        regs = {}
        for reg_name, reg_id in reg_map.items():
            try:
                regs[reg_name] = self.mu.reg_read(reg_id)
            except UcError as e:
                self.logger.error(f"Error reading register {reg_name.upper()}: {e}")
                regs[reg_name] = None

        return regs

    def read_memory(self, address, size):
        """
        Read memory from the emulated space.

        Args:
            address (int): Address to read from.
            size (int): Number of bytes to read.

        Returns:
            bytes: The data read from memory.
        """
        try:
            data = self.mu.mem_read(address, size)
            self.logger.debug(f"Read {size} bytes from {hex(address)}: {data.hex()}")
            return data
        except UcError as e:
            self.logger.error(f"Unicorn memory read error: {e}")
            return None

    def write_memory(self, address, data):
        """
        Write data to memory in the emulated space.

        Args:
            address (int): Address to write to.
            data (bytes): Data to write.
        """
        try:
            self.mu.mem_write(address, data)
            self.logger.debug(f"Wrote data to {hex(address)}: {data.hex()}")
        except UcError as e:
            self.logger.error(f"Unicorn memory write error: {e}")
            sys.exit(1)

    def set_stack(self, rsp_value=None, stack_address=0x0, stack_size=2 * 1024 * 1024):
        """
        Initialize the stack for the emulator.

        Args:
            rsp_value (int, optional): Initial value for RSP. Defaults to stack_address + stack_size.
            stack_address (int, optional): Base address for the stack.
            stack_size (int, optional): Size of the stack memory.
        """
        self.stack_address = stack_address
        self.stack_size = stack_size
        try:
            self.mu.mem_map(stack_address, stack_size)
            self.logger.debug(f"Stack memory mapped at {hex(stack_address)} with size {stack_size} bytes.")
        except UcError as e:
            self.logger.error(f"Unicorn stack memory mapping error: {e}")
            sys.exit(1)

        if rsp_value is None:
            rsp_value = stack_address + stack_size  # Typically stack grows downwards

        self.set_registers(rsp=rsp_value)
        self.logger.debug(f"Stack pointer (RSP) set to {hex(rsp_value)}.")

    def reset(self):
        """
        Reset the emulator to its initial state.
        """
        try:
            self.mu.emu_stop()
            self.mu = Uc(self.arch, self.mode)
            self.hooked = False
            self.logger.info("Emulator reset to initial state.")
        except UcError as e:
            self.logger.error(f"Error resetting emulator: {e}")
            sys.exit(1)
