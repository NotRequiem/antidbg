from pathlib import Path
import sys

def remove_type_lines(path: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="ignore")

    kept_lines = []
    for line in text.splitlines(True):  # keep line endings
        if ".type" not in line:
            kept_lines.append(line)

    p.write_text("".join(kept_lines), encoding="utf-8", newline="")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file>")
        raise SystemExit(1)

    remove_type_lines(sys.argv[1])