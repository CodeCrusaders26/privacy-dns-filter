"""Domain risk scoring and block decisions.

An optional model artifact can be supplied through ``load_model``. Model inputs
are the ordered numeric features returned by ``extract_features``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Protocol


FEATURE_NAMES = (
    "domain_length",
    "subdomain_count",
    "digit_ratio",
    "hyphen_count",
    "has_punycode",
    "has_suspicious_token",
    "suspicious_tld",
)

BLOCKLIST = frozenset(
    {
        "malware.test",
        "phishing.test",
        "credential-theft.test",
        "known-bad.example",
    }
)

SUSPICIOUS_TOKENS = (
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "wallet",
    "banking",
    "password",
    "support",
)
SUSPICIOUS_TLDS = frozenset({"zip", "mov", "click", "country", "top", "work"})
LABEL_PATTERN = re.compile(r"^[a-z0-9-]+$")


class RiskModel(Protocol):
    def predict_proba(self, samples: list[list[float]]) -> Any: ...


@dataclass(frozen=True)
class DomainDecision:
    domain: str
    action: str
    risk_score: int
    category: str
    reason: str
    model_name: str


def normalize_domain(domain: str) -> str:
    """Normalize a hostname, rejecting URL strings and malformed labels."""
    normalized = domain.strip().lower().rstrip(".")
    if normalized.startswith("*."):
        normalized = normalized[2:]
    if not normalized or len(normalized) > 253 or any(c in normalized for c in "/:@?#"):
        raise ValueError("Enter a hostname only, such as example.com.")
    labels = normalized.split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or not LABEL_PATTERN.fullmatch(label)
        or label.startswith("-") or label.endswith("-")
        for label in labels
    ):
        raise ValueError("Enter a valid fully qualified domain name.")
    return normalized


def extract_features(domain: str) -> list[float]:
    """Return the stable, ordered feature vector expected by model artifacts."""
    domain = normalize_domain(domain)
    labels = domain.split(".")
    host = ".".join(labels[:-1])
    return [
        float(len(domain)),
        float(max(0, len(labels) - 2)),
        sum(char.isdigit() for char in host) / max(1, len(host)),
        float(domain.count("-")),
        float("xn--" in domain),
        float(any(token in domain for token in SUSPICIOUS_TOKENS)),
        float(labels[-1] in SUSPICIOUS_TLDS),
    ]


class DNSFilter:
    """Evaluate domains using a model when available and a safe baseline otherwise."""

    def __init__(
        self,
        model: RiskModel | None = None,
        blocklist: frozenset[str] = BLOCKLIST,
        threshold: int = 70,
        model_name: str | None = None,
    ) -> None:
        if not 0 <= threshold <= 100:
            raise ValueError("threshold must be between 0 and 100")
        self.model = model
        self.blocklist = frozenset(normalize_domain(item) for item in blocklist)
        self.threshold = threshold
        self.model_name = model_name or ("Federated model" if model else "Heuristic baseline")

    def evaluate(self, domain: str) -> DomainDecision:
        normalized = normalize_domain(domain)
        if any(normalized == item or normalized.endswith(f".{item}") for item in self.blocklist):
            return DomainDecision(
                normalized, "Blocked", 100, "Known malicious",
                "Matched the local malicious-domain blocklist.", self.model_name,
            )

        features = extract_features(normalized)
        if self.model is not None:
            try:
                probability = float(self.model.predict_proba([features])[0][1])
            except (AttributeError, IndexError, TypeError, ValueError) as error:
                raise RuntimeError("The configured model could not score this domain.") from error
            risk_score = max(0, min(100, round(probability * 100)))
        else:
            risk_score = self._baseline_score(features)

        action = "Blocked" if risk_score >= self.threshold else "Allowed"
        category = "Suspicious" if risk_score >= self.threshold else "Benign"
        reason = (
            f"Risk score {risk_score}% meets the {self.threshold}% block threshold."
            if action == "Blocked"
            else f"Risk score {risk_score}% is below the {self.threshold}% block threshold."
        )
        return DomainDecision(normalized, action, risk_score, category, reason, self.model_name)

    @staticmethod
    def _baseline_score(features: list[float]) -> int:
        length, subdomains, digit_ratio, hyphens, punycode, token, suspicious_tld = features
        score = 8
        score += min(25, max(0, length - 18) * 1.5)
        score += min(15, subdomains * 5)
        score += min(20, digit_ratio * 50)
        score += min(12, hyphens * 4)
        score += punycode * 35
        score += token * 35
        score += suspicious_tld * 20
        return max(0, min(100, round(score)))


def load_model(path: str | Path) -> RiskModel:
    """Load a trusted scikit-learn-compatible model artifact using joblib."""
    try:
        import joblib
    except ImportError as error:
        raise RuntimeError("Install the optional model dependencies to load an artifact.") from error

    model_path = Path(path)
    if not model_path.is_file():
        raise FileNotFoundError(f"Model artifact not found: {model_path}")
    model = joblib.load(model_path)
    if not callable(getattr(model, "predict_proba", None)):
        raise TypeError("Model artifact must provide predict_proba.")
    return model
