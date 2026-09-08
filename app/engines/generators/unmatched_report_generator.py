import json
import os
from typing import Iterable, Mapping, Optional

from app.core.config import Config


def generate_unmatched_records(
    data: Iterable[Mapping[str, object]],
    output_dir: Optional[str] = None,
    filename: str = "unmatched_records.json",
) -> str:
    """Write unmatched correlation records to a JSON file."""
    unmatched = [record for record in data if record.get("status") == "NO_MATCH"]

    target_dir = output_dir or Config.OUTPUT_DIR
    os.makedirs(target_dir, exist_ok=True)
    output_path = os.path.join(target_dir, filename)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(unmatched, f, indent=4)

    return output_path
