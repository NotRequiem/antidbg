from pathlib import Path

root_dir = Path.cwd()
output_file = root_dir / "results.txt"

source_files = sorted(
    path for path in root_dir.rglob("*")
    if (
        path.is_file()
        and path.suffix.lower() in {".c", ".h"}
        and not any(part.lower() == "archived" for part in path.relative_to(root_dir).parts)
        and not path.name.lower().startswith("syscall")
    )
)

with output_file.open("w", encoding="utf-8") as results:
    for file_path in source_files:
        relative_path = file_path.relative_to(root_dir)

        results.write(f"\n{'=' * 80}\n")
        results.write(f"FILE: {relative_path}\n")
        results.write(f"{'=' * 80}\n\n")

        try:
            contents = file_path.read_text(encoding="utf-8", errors="replace")
            results.write(contents)

            if not contents.endswith("\n"):
                results.write("\n")

        except OSError as error:
            results.write(f"[Could not read file: {error}]\n")

print(f"Collected {len(source_files)} source files into {output_file}")
