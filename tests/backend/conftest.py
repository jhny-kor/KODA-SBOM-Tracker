from __future__ import annotations

import os
import tempfile
from pathlib import Path


TEST_ROOT = Path(tempfile.mkdtemp(prefix="koda-tracker-tests-"))
os.environ["TRACKER_DATABASE_URL"] = f"sqlite:///{TEST_ROOT / 'tracker.db'}"
os.environ["TRACKER_ARTIFACT_DIR"] = str(TEST_ROOT / "artifacts")
os.environ["TRACKER_BOOTSTRAP_ADMIN_USERNAME"] = "test-admin"
os.environ["TRACKER_BOOTSTRAP_ADMIN_PASSWORD"] = "correct-horse-battery-staple"
os.environ["TRACKER_SECURE_COOKIES"] = "false"
os.environ["TRACKER_DEPENDENCY_TRACK_URL"] = "http://dependency-track.test"
os.environ["TRACKER_DEPENDENCY_TRACK_API_KEY"] = "test-api-key"
