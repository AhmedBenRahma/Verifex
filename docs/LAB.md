# Lab setup

The lab runs two containers: **OWASP ZAP** (the scanner) and **OWASP Benchmark**
(the deliberately vulnerable target with a published answer key).

## 1. Set your ZAP API key

```bash
cp .env.example .env
# edit .env and set ZAP_API_KEY to any long random string
```

## 2. Bring the lab up

```bash
docker compose up -d --build
```

First run builds Benchmark from source (Maven downloads a lot — 10-20 min, once).
When it settles (Benchmark takes ~1-2 min to deploy on Tomcat):

- ZAP API: <http://localhost:8080>
- Benchmark (browser check): <http://localhost:8081/benchmark/>

Check both are reachable:

```bash
docker compose ps                       # both zap and benchmark should be "Up"
curl "http://localhost:8080/JSON/core/view/version/?apikey=$ZAP_API_KEY"
```

ZAP scans Benchmark inside the docker network at `http://benchmark:8080/benchmark/`
(the default TARGET_URL). You do not change that; port 8081 is only for your
own browser.

## 3. Run the scan

```bash
pip install -r requirements.txt
python -m scripts.run_scan
```

A full active scan of Benchmark takes **1-3 hours**. It runs unattended and
saves `data/benchmark_report.json`.

## 4. Build the labelled dataset

```bash
python -m src.build_dataset data/benchmark_report.json
```

This joins every alert to `data/expectedresults-1.2.csv` and writes
`data/dataset.csv` — the ground-truth-labelled training data.

## Notes

- ZAP is DAST, so it exercises the injection-family categories (SQLi, XSS,
  command injection, path traversal). SAST-only categories (weak randomness,
  weak hashing) produce no ZAP alerts and do not appear in the dataset — this
  is expected.
- Only scan targets you are authorised to test. This lab is fully local.
