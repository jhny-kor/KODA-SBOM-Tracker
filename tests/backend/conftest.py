from __future__ import annotations

import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet


TEST_ROOT = Path(tempfile.mkdtemp(prefix="koda-tracker-tests-"))
os.environ["TRACKER_ENVIRONMENT"] = "test"
os.environ["TRACKER_DATABASE_URL"] = f"sqlite:///{TEST_ROOT / 'tracker.db'}"
os.environ["TRACKER_ARTIFACT_DIR"] = str(TEST_ROOT / "artifacts")
os.environ["TRACKER_BOOTSTRAP_ADMIN_USERNAME"] = "test-admin"
os.environ["TRACKER_BOOTSTRAP_ADMIN_PASSWORD"] = "correct-horse-battery-staple"
os.environ["TRACKER_SECURE_COOKIES"] = "false"
# Legacy online-connector contract tests opt into online behavior explicitly.
# Closed-network tests override this setting and test the production default.
os.environ["TRACKER_OFFLINE_MODE"] = "false"
os.environ["TRACKER_LDAP_ENCRYPTION_KEY"] = Fernet.generate_key().decode("ascii")
KODA_PROVISIONING_TOKEN = TEST_ROOT / "koda-provisioning.token"
KODA_PROVISIONING_TOKEN.write_text("test-koda-provisioning-secret\n", encoding="utf-8")
os.environ["TRACKER_KODA_PROVISIONING_TOKEN_FILE"] = str(KODA_PROVISIONING_TOKEN)
