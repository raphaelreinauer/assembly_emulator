# Assembly Emulator

`assembly_emulator` is a Python package that allows you to assemble, emulate, and debug x86_64 assembly code using the Unicorn emulator and Keystone assembler. It provides logging and debugging functionalities to inspect arbitrary assembly instructions.

## Features

- **Assemble** x86_64 assembly code into machine code.
- **Emulate** the assembled code with Unicorn.
- **Log** executed instructions and register states.
- **Debug** by tracing instruction execution.
- **Modular** design for easy integration and testing.

## Installation

Ensure you have Python 3.6 or later installed.

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/$GITHUB_USERNAME/$REPO_NAME.git
   cd $REPO_NAME
   ```

2. **Install Dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Install the Package:**

   ```bash
   python setup.py install
   ```

   Or, for development mode:

   ```bash
   pip install -e .
   ```

## Usage

Here's an example of how to use the `AssemblyEmulator`:

```python
from assembly_emulator import AssemblyEmulator
import logging

def main():
      # Initialize the emulator with DEBUG logging level
      emulator = AssemblyEmulator(log_level=logging.DEBUG)

      # Map memory for code and stack
      CODE_ADDRESS = 0x1000000
      emulator.map_memory(address=CODE_ADDRESS, size=2 * 1024 * 1024)
      STACK_ADDRESS = 0x0
      emulator.set_stack(stack_address=STACK_ADDRESS, stack_size=2 * 1024 * 1024)

      # Assemble the desired assembly code
      assembly_code = """
         lea 7(%rdx, %rdx, 4), %rax
         ret
      """
      machine_code = emulator.assemble(assembly_code)

      # Load the machine code into the emulator's memory
      emulator.load_code(machine_code, address=CODE_ADDRESS)

      # Set initial register values
      emulator.set_registers(rdx=10, rip=CODE_ADDRESS)

      # Run the emulator
      emulator.run(start_address=CODE_ADDRESS, end_address=CODE_ADDRESS + len(machine_code))

      # Retrieve and print the register states after emulation
      final_regs = emulator.get_registers()
      print("Final Register States:")
      for reg, value in final_regs.items():
         print(f"{reg.upper():>4}: {value}")

      # Verify the result
      expected_rax = 7 + 5 * 10  # 7 + 5 * RDX
      actual_rax = final_regs['rax']
      print(f"\\nExpected RAX: {expected_rax}")
      print(f"Actual   RAX: {actual_rax}")

      if actual_rax == expected_rax:
         print("SUCCESS: LEAQ instruction executed correctly.")
      else:
         print("FAILURE: LEAQ instruction did not execute as expected.")

if __name__ == "__main__":
      main()
```

### Running the Example

Ensure all dependencies are installed, and then execute:

```bash
python example.py
```

Expected output:

```
2024-04-27 12:00:00,000 - AssemblyEmulator - INFO - Starting emulation from 0x1000000 to 0x1000007.
2024-04-27 12:00:00,010 - AssemblyEmulator - INFO - Executing instruction at 0x1000000: lea 7(%rdx, %rdx, 4), rax
2024-04-27 12:00:00,020 - AssemblyEmulator - DEBUG - Register States: RAX=0, RBX=0, RCX=0, RDX=10, RSI=0, RDI=0, RSP=2097152, RBP=0, R8=0, R9=0, R10=0, R11=0, R12=0, R13=0, R14=0, R15=0, RIP=0x1000007
2024-04-27 12:00:00,030 - AssemblyEmulator - INFO - Executing instruction at 0x1000007: ret
2024-04-27 12:00:00,040 - AssemblyEmulator - DEBUG - Register States: RAX=57, RBX=0, RCX=0, RDX=10, RSI=0, RDI=0, RSP=2097152, RBP=0, R8=0, R9=0, R10=0, R11=0, R12=0, R13=0, R14=0, R15=0, RIP=0x0
2024-04-27 12:00:00,050 - AssemblyEmulator - INFO - Emulation finished successfully.
Final Register States:
RAX : 57
RBX : 0
RCX : 0
RDX : 10
RSI : 0
RDI : 0
RSP : 2097152
RBP : 0
R8  : 0
R9  : 0
R10 : 0
R11 : 0
R12 : 0
R13 : 0
R14 : 0
R15 : 0
RIP : 0

Expected RAX: 57
Actual   RAX: 57
SUCCESS: LEAQ instruction executed correctly.
```