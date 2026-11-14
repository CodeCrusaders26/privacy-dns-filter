import unittest

from dns_filter.engine import DNSFilter, extract_features, normalize_domain


class FixedRiskModel:
    def predict_proba(self, samples):
        self.samples = samples
        return [[0.1, 0.9]]


class DNSFilterTests(unittest.TestCase):
    def test_normalizes_hostname(self):
        self.assertEqual(normalize_domain("  Example.COM. "), "example.com")

    def test_rejects_url_instead_of_hostname(self):
        with self.assertRaises(ValueError):
            normalize_domain("https://example.com/path")

    def test_known_bad_domain_is_blocked(self):
        decision = DNSFilter().evaluate("sub.malware.test")
        self.assertEqual(decision.action, "Blocked")
        self.assertEqual(decision.risk_score, 100)

    def test_benign_domain_is_allowed(self):
        decision = DNSFilter().evaluate("example.org")
        self.assertEqual(decision.action, "Allowed")

    def test_suspicious_domain_scores_higher_than_benign(self):
        benign = DNSFilter().evaluate("example.org")
        suspicious = DNSFilter().evaluate("secure-account-verify.top")
        self.assertGreater(suspicious.risk_score, benign.risk_score)
        self.assertEqual(suspicious.action, "Blocked")

    def test_feature_vector_has_stable_shape(self):
        self.assertEqual(len(extract_features("example.org")), 7)

    def test_uses_configured_model_and_block_threshold(self):
        model = FixedRiskModel()
        decision = DNSFilter(model=model, threshold=85).evaluate("example.org")
        self.assertEqual(decision.risk_score, 90)
        self.assertEqual(decision.action, "Blocked")
        self.assertEqual(len(model.samples[0]), 7)


if __name__ == "__main__":
    unittest.main()
