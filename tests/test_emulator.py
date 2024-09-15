import unittest
import logging
from assembly_emulator import AssemblyEmulator

class TestAssemblyEmulator(unittest.TestCase):
    def test_leaq_instruction(self):
        emulator = AssemblyEmulator(log_level=logging.DEBUG)
        emulator.map_memory(address=0x1000000, size=2 * 1024 * 1024)
        emulator.set_stack(stack_address=0x0, stack_size=2 * 1024 * 1024)

        assembly_code = """
            lea 7(%rdx, %rdx, 4), %rax
            ret
        """
        machine_code = emulator.assemble(assembly_code)
        emulator.load_code(machine_code, address=0x1000000)
        emulator.set_registers(rdx=10, rip=0x1000000)

        emulator.run(start_address=0x1000000, end_address=0x1000000 + len(machine_code))

        final_regs = emulator.get_registers()
        self.assertEqual(final_regs['rax'], 57)

if __name__ == '__main__':
    unittest.main()
