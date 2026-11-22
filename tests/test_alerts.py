"""Alerts: settings, threshold dispatch, Telegram one-time link. Run: python -m unittest discover -s tests -v"""
import asyncio
import os
import tempfile
import unittest
import uuid
from unittest.mock import AsyncMock, patch

_db = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_db}"

from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.database import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Analysis, Alert, ScanStatus, ScanType, Verdict  # noqa: E402


EMAIL = f"al-{uuid.uuid4().hex[:8]}@example.org"


class AlertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cm = TestClient(app)
        cls.client = cls.cm.__enter__()
        from app.core.security import create_access_token, hash_password
        from app.models import User, UserRole
        with SessionLocal() as db:
            u = User(email=EMAIL, password_hash=hash_password("x"), full_name="A", role=UserRole.user)
            db.add(u); db.commit()
            cls.h = {"Authorization": f"Bearer {create_access_token(u.id, 'user')}"}

    @classmethod
    def tearDownClass(cls):
        cls.cm.__exit__(None, None, None)

    def test_1_settings_defaults_and_unavailable_channels(self):
        s = self.client.get("/api/alerts/settings", headers=self.h).json()
        self.assertEqual(s["threshold"], 70)
        self.assertEqual(s["whatsapp"], "unavailable")
        self.assertEqual(s["email"], "unavailable")
        self.assertFalse(s["telegram_linked"])

    def test_2_threshold_and_slack_validation(self):
        r = self.client.put("/api/alerts/settings", headers=self.h, json={"threshold": 50})
        self.assertEqual(r.json()["threshold"], 50)
        bad = self.client.put("/api/alerts/settings", headers=self.h,
                              json={"slack_webhook_url": "http://169.254.169.254/x"})
        self.assertEqual(bad.status_code, 422)
        ok = self.client.put("/api/alerts/settings", headers=self.h,
                             json={"slack_webhook_url": "https://hooks.slack.com/services/T/B/x", "slack_enabled": True})
        self.assertTrue(ok.json()["slack_configured"])
        self.assertNotIn("hooks.slack.com", ok.text)

    def test_3_dispatch_respects_threshold(self):
        from app.engine.alerts import dispatch
        from sqlalchemy import select
        from app.models import User
        with SessionLocal() as db:
            u = db.execute(select(User).where(User.email == EMAIL)).scalar_one()
            self.client.put("/api/alerts/settings", headers=self.h, json={"threshold": 60})
            def mk(score):
                a = Analysis(user_id=u.id, input_type=ScanType.url, raw_input="http://evil.example/x",
                             normalized_input="x", request_hash=b"0" * 32, status=ScanStatus.done,
                             risk_score=score, verdict=Verdict.MALICIOUS)
                db.add(a); db.flush(); return a
            with patch("app.engine.alerts.send_slack", new=AsyncMock(return_value=True)) as sl:
                low = asyncio.run(dispatch(db, mk(59)))
                high = asyncio.run(dispatch(db, mk(85)))
            self.assertEqual(low, [])
            self.assertEqual(high, ["in_app", "slack"])
            self.assertEqual(sl.await_count, 1)
            db.commit()
        items = self.client.get("/api/alerts", headers=self.h).json()
        self.assertEqual(len(items["items"]), 1)
        self.assertEqual(items["unread"], 1)
        self.client.post("/api/alerts/read-all", headers=self.h)
        self.assertEqual(self.client.get("/api/alerts", headers=self.h).json()["unread"], 0)

    def test_4_telegram_link_one_time(self):
        with patch.object(settings, "telegram_bot_token", "x:test"), \
             patch.object(settings, "telegram_webhook_secret", "sec123"), \
             patch.object(settings, "telegram_bot_username", "TestBot"), \
             patch("app.api.alerts.send_telegram", new=AsyncMock(return_value=True)):
            c = self.client.post("/api/alerts/telegram/link-code", headers=self.h).json()
            code = c["code"]
            wrong = self.client.post("/api/telegram/webhook/nope", json={})
            self.assertEqual(wrong.status_code, 404)
            upd = {"message": {"text": f"/start {code}", "chat": {"id": 555, "type": "private"}}}
            self.client.post("/api/telegram/webhook/sec123", json=upd)
            self.assertTrue(self.client.get("/api/alerts/settings", headers=self.h).json()["telegram_linked"])
            # الكود مرة واحدة: مستخدم تاني بنفس الكود ما يربطش
            self.client.post("/api/alerts/telegram/unlink", headers=self.h)
            upd2 = {"message": {"text": f"/start {code}", "chat": {"id": 777, "type": "private"}}}
            self.client.post("/api/telegram/webhook/sec123", json=upd2)
            self.assertFalse(self.client.get("/api/alerts/settings", headers=self.h).json()["telegram_linked"])


if __name__ == "__main__":
    unittest.main()
