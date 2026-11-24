import os, unittest
from fastapi.testclient import TestClient
from app.main import app


class AdminTests(unittest.TestCase):
    def setUp(self):
        self._cm = TestClient(app)
        self.c = self._cm.__enter__()
        self.addCleanup(self._cm.__exit__, None, None, None)

    def test_disabled_without_token(self):
        os.environ.pop("ADMIN_TOKEN", None)
        self.assertEqual(self.c.get("/api/admin/overview").status_code, 404)
        self.assertEqual(self.c.get("/admin").status_code, 404)

    def test_auth(self):
        os.environ["ADMIN_TOKEN"] = "x" * 32
        self.assertEqual(self.c.get("/api/admin/overview").status_code, 401)
        self.assertEqual(self.c.get("/api/admin/overview", headers={"X-Admin-Token": "y" * 32}).status_code, 401)
        r = self.c.get("/api/admin/overview", headers={"X-Admin-Token": "x" * 32})
        self.assertEqual(r.status_code, 200)
        self.assertIn("totals", r.json())
        self.assertEqual(self.c.get("/admin").status_code, 200)
        os.environ.pop("ADMIN_TOKEN", None)

    def test_failed_login_logged(self):
        self.c.post("/api/auth/login", json={"email": "nobody@example.com", "password": "wrongpass123"})
        os.environ["ADMIN_TOKEN"] = "z" * 32
        ev = self.c.get("/api/admin/overview", headers={"X-Admin-Token": "z" * 32}).json()["events"]
        self.assertTrue(any(e["action"] == "login_failed_unknown" for e in ev))
        os.environ.pop("ADMIN_TOKEN", None)


if __name__ == "__main__":
    unittest.main()
