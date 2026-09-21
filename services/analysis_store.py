import threading
import uuid

class AnalysisStore:
    """In-memory analysis sessions. No Rapid7 data is written to persistent storage."""
    def __init__(self, max_sessions=5):
        self._lock = threading.Lock()
        self._sessions = {}
        self._order = []
        self.max_sessions = max_sessions

    def create(self, analysis):
        session_id = uuid.uuid4().hex
        with self._lock:
            self._sessions[session_id] = analysis
            self._order.append(session_id)
            while len(self._order) > self.max_sessions:
                old = self._order.pop(0)
                self._sessions.pop(old, None)
        return session_id

    def get(self, session_id):
        with self._lock:
            return self._sessions.get(session_id)
