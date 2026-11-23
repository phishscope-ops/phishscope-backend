"""Trusted-platform discount must never cover look-alikes, redirectors to foreign targets, or userinfo tricks."""
import unittest

from app.analysis.trusted import trusted_platform
from app.analysis.url_features import extract_url_features, static_url_findings

OK = [
    "https://www.instagram.com/reel/C8abcDEfGhI/?igsh=MTIzNDU2Nzg5MA==",
    "https://www.instagram.com/p/C8abc/?utm_source=ig_web_copy_link",
    "https://www.instagram.com/tv/CabcDEfGhI/",
    "https://www.instagram.com/share/reel/BAbCdEfGhI/",
    "https://instagr.am/p/C8abcDEfGhI/",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://youtu.be/dQw4w9WgXcQ?si=abcdEFG",
    "https://www.facebook.com/watch/?v=1234567890",
    "https://m.facebook.com/story.php?story_fbid=pfbid02abc&id=1&mibextid=WC7FNe",
    "https://www.tiktok.com/@user/video/7234567890123456789",
    "https://vm.tiktok.com/ZMabcdef/",
    "https://x.com/user/status/1234567890123456789",
    "https://web.whatsapp.com/",
    "https://wa.me/201001234567",
    "https://l.instagram.com/?u=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3Dabc&e=AT0x",
]
BAD = [
    "https://l.instagram.com/?u=https%3A%2F%2Fevil-login.tk%2F&e=AT0x",
    "https://l.facebook.com/l.php?u=https%3A%2F%2Fevil.example%2Fpay",
    "https://www.youtube.com/redirect?q=http%3A%2F%2Fevil.ml%2F",
    "https://instagram.com.evil-login.tk/reel/abc/",
    "https://evilinstagram.com/reel/abc/",
    "https://instagram.com@evil.tk/reel/abc/",
    "http://www.instagram.com/reel/abc/",
    "https://instagram-security-check.com/verify",
    "https://docs.google.com/forms/d/abc",
    "https://paypal.com.secure-update.ml/login",
]


class TrustedTests(unittest.TestCase):
    def test_trusted(self):
        for u in OK:
            self.assertIsNotNone(trusted_platform(u), u)

    def test_not_trusted(self):
        for u in BAD:
            self.assertIsNone(trusted_platform(u), u)

    def test_at_symbol_rule_only_in_authority(self):
        u = "https://www.tiktok.com/@user/video/1"
        self.assertNotIn("AT_SYMBOL", {f["rule"] for f in static_url_findings(u, extract_url_features(u))})
        u2 = "http://google.com@evil.tk/login"
        self.assertIn("AT_SYMBOL", {f["rule"] for f in static_url_findings(u2, extract_url_features(u2))})


if __name__ == "__main__":
    unittest.main()
