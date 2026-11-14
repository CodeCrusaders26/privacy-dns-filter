# Aegis DNS privacy filter

A runnable Streamlit demo for a privacy-first DNS filtering workflow. It includes
a local domain-scoring engine, blocklist decisions, interactive domain checks,
filtering logs, and a federated-model status dashboard. Federated metrics and
sample traffic are illustrative; the demo does not connect to a DNS resolver or
send data to a central server.

## Run locally

On Windows, a short virtual-environment path avoids long-path issues with some
Python installations:

```powershell
python -m venv C:\dns-filter-env
C:\dns-filter-env\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run dashboard/app.py
```

The dashboard opens in your browser. Use **Quick domain check** to test a
hostname; `malware.test` is included in the demo blocklist, and suspicious
hostnames are scored against a local heuristic baseline.

## Use a compatible trained model

Place a trusted scikit-learn-compatible model artifact at
`models/domain_model.joblib`. The model must provide `predict_proba` and accept
the seven numeric features emitted by `dns_filter.engine.extract_features`, in
this order:

1. Domain length
2. Subdomain count
3. Digit ratio in the host portion
4. Hyphen count
5. Punycode indicator
6. Suspicious-token indicator
7. Suspicious top-level-domain indicator

For binary classification, the positive-class probability (`predict_proba`
column 1) is treated as malicious risk. Artifacts are loaded with `joblib`; only
load model files you trust. Without an artifact, the app uses the heuristic
baseline. The dashboard's federated-learning metrics are example UI data, not
results from a running training coordinator.

## Tests

```powershell
python -m unittest discover -s tests
```
