import re
import os
import sys
import argparse
import logging
from typing import List, Optional, Iterator

# Basically converts SysWhispers3's function prototypes to macros that are compatible with every compiler

# --- Configuration ---
DEFAULT_INPUT_FILENAME = 'syscalls.h'
DEFAULT_OUTPUT_FILENAME = 'syscalls_converted.h'
# ---------------------

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

class SyscallConverter:
    def __init__(self, input_path: str, output_path: str):
        self.input_path = input_path
        self.output_path = output_path
        self.main_pattern = re.compile(
            r'EXTERN_C\s+'        # Literal text
            r'(.*?)'              # Group 1: The return type (non-greedy)
            r'\s*DbgNt(\w+)\s*'    # Group 2: The function name
            r'\(([\s\S]*?)\);',   # Group 3: The full argument string
            re.MULTILINE
        )

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
        final_output_parts: List[str] = []
        try:
            matches = self.main_pattern.finditer(content)
        except re.error as e:
            logging.error(f"A regex error occurred: {e}")
            return ""

        for match in matches:
            final_output_parts.extend(self._format_match(match))

        logging.info(f"Successfully processed {len(final_output_parts) // 4} function prototypes.")
        return "\n".join(final_output_parts)

    def _format_match(self, match: re.Match) -> List[str]:
        ret_type_raw: str = match.group(1).strip()
        name: str = match.group(2).strip()
        args_raw: str = match.group(3).strip()

        ret_type = re.sub(r'\b(NTAPI)\b', '', ret_type_raw).strip()
        args_clean = re.sub(r'\b(IN|OUT|IN OUT|OPTIONAL)\b', '', args_raw)

        args_list = [arg.strip() for arg in args_clean.split(',') if arg.strip()]
        final_args = [' '.join(arg.split()) for arg in args_list if arg.strip().upper() != 'VOID']

        macro_lines: List[str] = []
        macro_lines.append(f"SYSCALL_DEFINE({name},")
        macro_lines.append(f"    {ret_type}{',' if final_args else ''}")

        if final_args:
            for i, arg in enumerate(final_args):
                comma = "," if i < len(final_args) - 1 else ""
                macro_lines.append(f"    {arg}{comma}")

        macro_lines.append(")")
        macro_lines.append("")
        return macro_lines

    def _write_output_content(self, content: str) -> bool:
        logging.info(f"Attempting to write the output file: '{self.output_path}'")
        try:
            with open(self.output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logging.info(f"Conversion is complete. The result is in '{self.output_path}'")
            return True
        except PermissionError:
            logging.error(f"Permission denied to write the output file: '{self.output_path}'")
        except IOError as e:
            logging.error(f"An I/O error occurred while writing the file: {e}")
        return False

    def run_conversion(self) -> bool:
        logging.info(f"--- Starting conversion of '{self.input_path}' ---")
        
        source_content = self._read_source_content()
        if source_content is None:
            return False

        transformed_content = self._parse_and_transform(source_content)
        if not transformed_content:
            logging.warning("No function prototypes were found or transformed. The output file will be empty.")

        return self._write_output_content(transformed_content)

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Converts SysWhispers3 function prototypes to a generic macro format."
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
        help=f"Output header file name (default: {DEFAULT_OUTPUT_FILENAME})"
    )
    args = parser.parse_args()

    converter = SyscallConverter(input_path=args.input, output_path=args.output)
    success = converter.run_conversion()

    if not success:
        logging.error("Conversion process failed.")
        sys.exit(1)
    else:
        logging.info("Conversion process completed successfully.")
        sys.exit(0)

if __name__ == "__main__":
    main()