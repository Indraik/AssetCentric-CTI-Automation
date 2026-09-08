import os
from typing import Iterable, Mapping, Optional

from app.core.config import Config


def generate_yara_rules(
    data: Iterable[Mapping[str, object]],
    output_dir: Optional[str] = None,
    filename: str = "yara_rules.yar",
) -> str:
    """Generate a YARA rule file from correlation results."""
    target_dir = output_dir or Config.OUTPUT_DIR
    os.makedirs(target_dir, exist_ok=True)
    output_path = os.path.join(target_dir, filename)

    hashes = set()
    for record in data:
        if record.get("status") == "MATCH":
            if record.get("type") == "hash" and record.get("indicator"):
                hashes.add(str(record.get("indicator")))
            log = record.get("log_record", {})
            if isinstance(log, dict) and "file_hash" in log:
                file_hash = log.get("file_hash")
                if file_hash:
                    hashes.add(str(file_hash))

    lines = [
        "rule Malicious_Hashes\n",
        "{\n",
        "    strings:\n",
    ]

    for i, h in enumerate(sorted(hashes)):
        lines.append(f'        $hash{i} = "{h}"\n')

    if not hashes:
        lines.append("        // No matched file hashes were found in endpoint logs.\n")

    lines.append("\n    condition:\n")
    lines.append("        any of them\n" if hashes else "        false\n")
    lines.append("}\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # Legacy copy for compatibility
    if target_dir != Config.LEGACY_OUTPUT_DIR:
        try:
            os.makedirs(Config.LEGACY_OUTPUT_DIR, exist_ok=True)
            with open(os.path.join(Config.LEGACY_OUTPUT_DIR, filename), "w", encoding="utf-8") as f:
                f.writelines(lines)
        except Exception:
            pass

    return output_path
