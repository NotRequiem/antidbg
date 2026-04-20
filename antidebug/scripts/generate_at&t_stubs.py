import re
import sys
import argparse
import logging
from typing import List, Optional

DEFAULT_INPUT_FILENAME = 'syscalls.h'
DEFAULT_OUTPUT_FILENAME = 'syscalls.S'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

class SyscallAsmGenerator:
    def __init__(self, input_path: str, output_path: str):
        self.input_path = input_path
        self.output_path = output_path
        
        # matches "SYSCALL_DEFINE(FunctionName," 
        # since the second arg is always the return type, there's always at least one comma
        self.main_pattern = re.compile(r'SYSCALL_DEFINE\s*\(\s*([a-zA-Z0-9_]+)\s*,')

    def _hash_syscall(self, name: str) -> int:
        """
        DWORD __hash_syscall(PCSTR FunctionName)
        """
        seed = 0x28C5192F
        hash_val = seed
        
        # add two null bytes so we can safely read WORDs (2 bytes) even at the end of the string
        name_bytes = name.encode('utf-8') + b'\x00\x00'
        
        i = 0
        while name_bytes[i] != 0:
            # read 2 bytes (WORD) exactly like: WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++)
            partial_name = name_bytes[i] | (name_bytes[i+1] << 8)
            i += 1
            
            # dbg_ROR8(Hash)
            ror8_val = ((hash_val >> 8) | (hash_val << 24)) & 0xFFFFFFFF
            
            # Hash ^= PartialName + Dbg_ROR8(Hash)
            hash_val ^= (partial_name + ror8_val) & 0xFFFFFFFF
            hash_val &= 0xFFFFFFFF # Ensure it stays a 32-bit DWORD
            
        return hash_val

    def _read_source_content(self) -> Optional[str]:
        logging.info(f"Attempting to read the input file: '{self.input_path}'")
        try:
            with open(self.input_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            logging.info("Successfully read the input file.")
            return content
        except FileNotFoundError:
            logging.error(f"Input file not found: '{self.input_path}'")
        except PermissionError:
            logging.error(f"Permission denied to read the input file: '{self.input_path}'")
        except IOError as e:
            logging.error(f"An I/O error occurred while reading the file: {e}")
        return None

    def _parse_and_transform(self, content: str) -> str:
        try:
            matches = list(self.main_pattern.finditer(content))
        except re.error as e:
            logging.error(f"A regex error occurred: {e}")
            return ""

        output_lines: List[str] = [
            ".text",          # tell the assembler this is executable code
            ""
        ]

        for match in matches:
            base_name = match.group(1).strip()
            
            # The hash algorithm expects the "Zw" prefix
            zw_name = f"Zw{base_name}"
            hash_val = self._hash_syscall(zw_name)
            
            # AT&T assembly format for GCC/Clang
            stub = f""".global DbgNt{base_name}
.type DbgNt{base_name}, @function
DbgNt{base_name}:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x{hash_val:08X}, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret
"""
            output_lines.append(stub)

        logging.info(f"Successfully generated assembly stubs for {len(matches)} syscalls.")
        return "\n".join(output_lines)

    def _write_output_content(self, content: str) -> bool:
        logging.info(f"Attempting to write the output file: '{self.output_path}'")
        try:
            with open(self.output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logging.info(f"Generation is complete. The result is in '{self.output_path}'")
            return True
        except PermissionError:
            logging.error(f"Permission denied to write the output file: '{self.output_path}'")
        except IOError as e:
            logging.error(f"An I/O error occurred while writing the file: {e}")
        return False

    def run_generation(self) -> bool:
        logging.info(f"Starting generation of GCC Assembly from '{self.input_path}'")
        
        source_content = self._read_source_content()
        if source_content is None:
            return False

        transformed_content = self._parse_and_transform(source_content)
        if not transformed_content:
            logging.warning("No function macros were found. The output file will be essentially empty.")

        return self._write_output_content(transformed_content)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generates GNU AT&T (.S) syscall stubs for GCC/Clang from syscalls.h macros."
    )
    parser.add_argument(
        '-i', '--input',
        type=str,
        default=DEFAULT_INPUT_FILENAME,
        help=f"Input header file name (default: {DEFAULT_INPUT_FILENAME})"
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        default=DEFAULT_OUTPUT_FILENAME,
        help=f"Output assembly file name (default: {DEFAULT_OUTPUT_FILENAME})"
    )
    args = parser.parse_args()

    generator = SyscallAsmGenerator(input_path=args.input, output_path=args.output)
    success = generator.run_generation()

    if not success:
        logging.error("Generation process failed.")
        sys.exit(1)
    else:
        logging.info("Generation process completed successfully.")
        sys.exit(0)

if __name__ == "__main__":
    main()