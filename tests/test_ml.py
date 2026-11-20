import unittest

from ml.url_features import extract_features
from ml.predict_url import FEATURE_NAMES, predict_url, model


class URLFeatureTests(unittest.TestCase):
    def test_feature_schema_matches_model(self):
        features = extract_features("https://www.example.com/login")
        self.assertEqual(list(features.keys()), FEATURE_NAMES)
        self.assertEqual(len(features), getattr(model, "n_features_in_", len(FEATURE_NAMES)))

    def test_www_normalization(self):
        self.assertEqual(
            extract_features("https://www.example.com"),
            extract_features("https://example.com"),
        )

    def test_prediction_shape_and_probability_range(self):
        result = predict_url("https://www.google.com")
        self.assertIn(result["prediction"], {"SAFE", "PHISHING"})
        self.assertGreaterEqual(result["phishing_probability"], 0.0)
        self.assertLessEqual(result["phishing_probability"], 100.0)

    def test_prediction_is_repeatable(self):
        url = "http://192.0.2.10/login/verify"
        self.assertEqual(predict_url(url), predict_url(url))


if __name__ == "__main__":
    unittest.main()
