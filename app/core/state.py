import threading
from typing import Any, Dict

# Thread-safe pipeline run state
pipeline_state_lock = threading.Lock()

pipeline_state: Dict[str, Any] = {
    "running": False,
    "last_run": None,
    "message": "Idle",
}


def get_pipeline_state() -> Dict[str, Any]:
    with pipeline_state_lock:
        return dict(pipeline_state)


def set_pipeline_state(running: bool, message: str, last_run: Any = None):
    with pipeline_state_lock:
        pipeline_state["running"] = running
        pipeline_state["message"] = message
        if last_run is not None:
            pipeline_state["last_run"] = last_run
