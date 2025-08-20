import re
import os

# Basically converts SysWhispers3's function prototypes to macros that are compatible with every compiler

# --- Configuration ---
INPUT_FILENAME = 'syscalls.h'
OUTPUT_FILENAME = 'syscalls_converted.h'
# ---------------------

def run_conversion():
    print(f"--- Starting conversion of '{INPUT_FILENAME}' ---")

    if not os.path.exists(INPUT_FILENAME):
        print(f"[ERROR] Input file not found: '{INPUT_FILENAME}'")
        return

    try:
        with open(INPUT_FILENAME, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        print("[1/3] Successfully read the input file.")
    except Exception as e:
        print(f"[ERROR] Could not read the input file: {e}")
        return

    main_pattern = re.compile(
        r'EXTERN_C\s+'        # Literal text
        r'(.*?)'              # Group 1: The return type (non-greedy)
        r'\s*DbgNt(\w+)\s*'    # Group 2: The function name
        r'\(([\s\S]*?)\);',   # Group 3: The full argument string
        re.MULTILINE
    )

    final_output_parts = []
    matches = main_pattern.finditer(content)
    
    for match in matches:
        ret_type_raw = match.group(1).strip()
        name = match.group(2).strip()
        args_raw = match.group(3).strip()

        ret_type = re.sub(r'\b(NTAPI)\b', '', ret_type_raw).strip()

        args_clean = re.sub(r'\b(IN|OUT|IN OUT|OPTIONAL)\b', '', args_raw)
        
        args_list = [arg.strip() for arg in args_clean.split(',') if arg.strip()]

        final_args = [ ' '.join(arg.split()) for arg in args_list if arg.strip().upper() != 'VOID' ]
        
        final_output_parts.append(f"SYSCALL_DEFINE({name},")
        final_output_parts.append(f"    {ret_type}{',' if final_args else ''}")

        if final_args:
            for i, arg in enumerate(final_args):
                # comma to all arguments except the last one
                comma = "," if i < len(final_args) - 1 else ""
                final_output_parts.append(f"    {arg}{comma}")
        
        final_output_parts.append(")")
        final_output_parts.append("")

    print("[2/3] Successfully processed all function prototypes.")

    final_content = "\n".join(final_output_parts)
    with open(OUTPUT_FILENAME, 'w', encoding='utf-8') as f:
        f.write(final_content)

    print(f"Conversion is complete. The result is in '{OUTPUT_FILENAME}'")

if __name__ == "__main__":
    run_conversion()