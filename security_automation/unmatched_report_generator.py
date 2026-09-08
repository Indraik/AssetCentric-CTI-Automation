import json
import os
from typing import Iterable, Mapping, Optional


def generate_unmatched_records(
    data: Iterable[Mapping[str, object]],
    output_dir: Optional[str] = None,
    filename: str = "unmatched_records.json",
):
    """Write unmatched correlation records to a JSON file."""

    unmatched = [record for record in data if record.get("status") == "NO_MATCH"]

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
    else:
        output_path = filename

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(unmatched, f, indent=4)

    print(f"[+] Unmatched records file generated: {output_path}")
