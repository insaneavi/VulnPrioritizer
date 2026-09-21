import os
import pickle
import tempfile
import uuid
from pathlib import Path

class AnalysisStore:
    """
    Shared temporary analysis-session storage.

    Sessions are stored under the container's /tmp filesystem so all Gunicorn
    workers can access the same analysis. This directory is NOT mapped to a
    Docker volume and disappears when the container is recreated.
    """
    def __init__(self, max_sessions=5, root=None):
        self.max_sessions = max_sessions
        self.root = Path(root or os.environ.get(
            "ANALYSIS_TMP_ROOT",
            os.path.join(tempfile.gettempdir(), "vulnprioritizer_sessions")
        ))
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, session_id):
        # UUID hex IDs only; prevents path traversal.
        if not session_id or any(c not in "0123456789abcdef" for c in session_id.lower()):
            return None
        return self.root / f"{session_id.lower()}.pkl"

    def _cleanup(self):
        files = sorted(
            self.root.glob("*.pkl"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        for old in files[self.max_sessions:]:
            try:
                old.unlink()
            except FileNotFoundError:
                pass

    def create(self, analysis):
        session_id = uuid.uuid4().hex
        final_path = self.root / f"{session_id}.pkl"
        temp_path = self.root / f".{session_id}.tmp"

        # Atomic write prevents another worker from observing a partial session.
        with open(temp_path, "wb") as handle:
            pickle.dump(analysis, handle, protocol=pickle.HIGHEST_PROTOCOL)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, final_path)
        self._cleanup()
        return session_id

    def get(self, session_id):
        path = self._path(session_id)
        if path is None or not path.exists():
            return None
        try:
            with open(path, "rb") as handle:
                return pickle.load(handle)
        except (FileNotFoundError, EOFError, pickle.UnpicklingError):
            return None
