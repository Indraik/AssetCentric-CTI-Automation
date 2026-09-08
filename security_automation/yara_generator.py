import os
from typing import Iterable, Mapping, Optional


def generate_yara_rules(
    data: Iterable[Mapping[str, object]],
    output_dir: Optional[str] = None,
    filename: str = "yara_rules.yar",
):
    """Generate a YARA rule file from correlation results."""

    hashes = set()
    for record in data:
        if record.get("status") == "MATCH":
            if record.get("type") == "hash" and record.get("indicator"):
                hashes.add(str(record.get("indicator")))
            log = record.get("log_record", {})
            if "file_hash" in log:
                file_hash = log.get("file_hash")
                if file_hash:
                    hashes.add(str(file_hash))

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
    else:
        output_path = filename

    with open(output_path, "w") as f:
        f.write("rule Malicious_Hashes\n{\n")
        f.write("    strings:\n")

        for i, h in enumerate(sorted(hashes)):
            f.write(f'        $hash{i} = "{h}"\n')

        if not hashes:
            f.write("        // No matched file hashes were found in endpoint logs.\n")

        f.write("\n    condition:\n")
        f.write("        any of them" if hashes else "        false")
        f.write("}\n")

    print(f"[+] YARA rule file generated: {output_path}")
