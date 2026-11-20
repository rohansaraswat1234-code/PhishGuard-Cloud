import unittest

try:
    from backend.app import app, is_valid_url
except ImportError as import_error:
    app = None
    IMPORT_ERROR = import_error
else:
    IMPORT_ERROR = None


@unittest.skipIf(app is None, f"Flask application dependencies unavailable: {IMPORT_ERROR}")
class CSRFSecurityTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = app.test_client()

    def test_post_without_csrf_token_is_rejected(self):
        response = self.client.post("/user/login", data={"email": "nobody@example.com", "password": "wrong"})
        self.assertEqual(response.status_code, 403)

    def test_post_with_session_csrf_token_reaches_route(self):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "unit-test-token"
        response = self.client.post(
            "/user/login",
            data={"csrf_token": "unit-test-token", "email": "nobody@example.com", "password": "wrong"},
        )
        self.assertNotEqual(response.status_code, 403)

    def test_security_headers_are_present(self):
        response = self.client.get("/")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")

    def test_url_validator_rejects_malformed_inputs(self):
        self.assertTrue(is_valid_url("https://example.com/path"))
        self.assertTrue(is_valid_url("HTTPS://example.com"))
        self.assertFalse(is_valid_url("https://999.999.999.999"))
        self.assertFalse(is_valid_url("https://127.1"))
        self.assertFalse(is_valid_url("https://example.123"))
        self.assertFalse(is_valid_url("https://example.com:bad"))
        self.assertFalse(is_valid_url("https://user:pass@example.com"))
        self.assertFalse(is_valid_url("not a url"))


if __name__ == "__main__":
    unittest.main()
