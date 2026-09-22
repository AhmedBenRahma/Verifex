"""
Smart Security Testing Module - SOC / red-team console.

    python -m streamlit run dashboard/app.py

Real model output only. Upload a ZAP JSON report (or use the bundled sample) and
the trained model triages it live: real findings vs noise, per-finding
explainability (SHAP), re-verification payloads, and held-out performance.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src import config
from src.benchmark_labeller import CWE_TO_CATEGORY, iter_alerts
from src.features import FEATURE_COLUMNS, extract_features
from src.payloads import suggest

# --- palette ---------------------------------------------------------------
BG = "#0a0e14"
GREEN = "#00ff9d"
CYAN = "#00e5ff"
RED = "#ff4d6d"
AMBER = "#ffb703"
MUTED = "#8b949e"

st.set_page_config(page_title="Smart Security Testing Module", page_icon="shield", layout="wide")

st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
.stApp {{ background-color:{BG}; background-image:
  linear-gradient(rgba(0,255,157,0.035) 1px, transparent 1px),
  linear-gradient(90deg, rgba(0,255,157,0.035) 1px, transparent 1px);
  background-size:38px 38px; }}
html, body, [class*="css"], .stMarkdown, .stDataFrame {{ font-family:'JetBrains Mono','Consolas',monospace; }}
h1,h2,h3 {{ color:{GREEN} !important; text-shadow:0 0 10px rgba(0,255,157,0.45); letter-spacing:1px; }}
section[data-testid="stSidebar"] {{ background-color:#0d1117; border-right:1px solid #00ff9d33; }}
.kpi {{ background:linear-gradient(180deg,#0d1117,#0a0e14); border:1px solid #00ff9d44;
  border-radius:10px; padding:14px 16px; box-shadow:0 0 16px rgba(0,255,157,0.08) inset; }}
.kpi .label {{ color:{MUTED}; font-size:0.8rem; text-transform:uppercase; letter-spacing:2px; }}
.kpi .value {{ color:{GREEN}; font-size:2.1rem; font-weight:700; text-shadow:0 0 12px rgba(0,255,157,0.4); }}
.kpi.red .value {{ color:{RED}; text-shadow:0 0 12px rgba(255,77,109,0.4); }}
.kpi.cyan .value {{ color:{CYAN}; text-shadow:0 0 12px rgba(0,229,255,0.4); }}
.termbar {{ color:{GREEN}; border-bottom:1px solid #00ff9d33; padding-bottom:4px; margin-bottom:10px; }}
div[data-testid="stDataFrame"] {{ border:1px solid #00ff9d33; border-radius:8px; }}
.badge {{ padding:2px 8px; border-radius:4px; font-weight:700; font-size:0.8rem; }}
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def load_model():
    if not config.MODEL_PATH.exists():
        return None
    return joblib.load(config.MODEL_PATH)


@st.cache_resource
def load_metrics():
    p = config.MODELS_DIR / "metrics.json"
    return json.load(open(p)) if p.exists() else {}


def classify(alerts, model):
    feats = [extract_features(a) for a in alerts]
    X = pd.DataFrame(feats, columns=FEATURE_COLUMNS)
    proba = model.predict_proba(X)[:, 1]
    pred = model.predict(X)
    rows = []
    for a, p, pr in zip(alerts, pred, proba):
        inst = (a.get("instances") or [{}])[0]
        cwe = int(a.get("cweid", 0) or 0)
        rows.append({
            "Vulnerability": a.get("name", "Unknown"),
            "URL": a.get("url") or inst.get("uri", ""),
            "Risk": a.get("risk") or {3: "High", 2: "Medium", 1: "Low", 0: "Info"}.get(int(a.get("riskcode", 0) or 0), ""),
            "Verdict": "REAL" if p == 1 else "NOISE",
            "Confidence": float(pr),
            "Category": CWE_TO_CATEGORY.get(cwe, "other"),
        })
    return pd.DataFrame(rows), X


# =========================================================================
st.markdown(f"<div class='termbar'>root@ssvm:~$ ./triage --model gradient-boosting</div>", unsafe_allow_html=True)
st.title("Smart Security Testing Module")
st.caption("AI triage of OWASP ZAP findings — real model output, trained on OWASP Benchmark")

bundle = load_model()
if bundle is None:
    st.error("No trained model found. Run:  python -m src.train")
    st.stop()
model, model_name = bundle["model"], bundle["name"]

with st.sidebar:
    st.markdown("## Input")
    st.caption(f"Model loaded: {model_name}")
    uploaded = st.file_uploader("ZAP report (JSON)", type=["json"])
    sample_path = config.DATA_DIR / "sample_report.json"
    use_sample = st.checkbox("Use bundled sample report", value=uploaded is None)

report = None
source = ""
if uploaded is not None and not use_sample:
    report = json.load(uploaded); source = uploaded.name
elif use_sample and sample_path.exists():
    report = json.load(open(sample_path, encoding="utf-8")); source = "sample_report.json"
elif uploaded is not None:
    report = json.load(uploaded); source = uploaded.name

if report is None:
    st.info("Upload a ZAP JSON report, or tick **Use bundled sample report**, to begin.")
    st.stop()

alerts = list(iter_alerts(report))
if not alerts:
    st.warning("No alerts found in that report.")
    st.stop()

df, X = classify(alerts, model)
total = len(df)
real = int((df["Verdict"] == "REAL").sum())
noise = total - real
reduction = (1 - real / total) * 100 if total else 0

# --- KPI row ---------------------------------------------------------------
st.caption(f"source: {source}")
k = st.columns(5)
tiles = [
    ("Total alerts", f"{total:,}", ""),
    ("Real findings", f"{real}", "red"),
    ("Noise filtered", f"{noise:,}", "cyan"),
    ("Review reduction", f"{reduction:.0f}%", ""),
    ("Model", model_name.split()[0], "cyan"),
]
for col, (label, value, cls) in zip(k, tiles):
    col.markdown(f"<div class='kpi {cls}'><div class='label'>{label}</div><div class='value'>{value}</div></div>", unsafe_allow_html=True)

if real == 0:
    st.warning("The model flagged **no real findings** in this report. If this is not "
               "an OWASP Benchmark scan, that is expected — the model is trained on "
               "Benchmark and treats out-of-distribution alerts as noise.")

st.divider()

# --- Triage table ----------------------------------------------------------
st.header("Triaged findings")
view = st.radio("Filter", ["All", "Real findings", "Noise"], horizontal=True, index=0)
shown = df
if view == "Real findings":
    shown = df[df["Verdict"] == "REAL"]
elif view == "Noise":
    shown = df[df["Verdict"] == "NOISE"]
shown = (shown.assign(_r=(shown["Verdict"] == "NOISE"))
              .sort_values(["_r", "Confidence"], ascending=[True, False])
              .drop(columns="_r"))

shown_display = shown.copy()
shown_display["Confidence"] = (shown_display["Confidence"] * 100).round(0)

st.dataframe(
    shown_display, use_container_width=True, hide_index=True, height=380,
    column_config={
        "Confidence": st.column_config.ProgressColumn(
            "Confidence", min_value=0, max_value=100, format="%d%%"),
        "Verdict": st.column_config.TextColumn("Verdict"),
        "URL": st.column_config.TextColumn("URL", width="large"),
    },
)
st.caption("Verdict REAL = model-confirmed finding · NOISE = passive / false positive")

from src.report import build_report
report_html = build_report(source, df.to_dict("records"), None, {"model": model_name})
st.download_button("⬇ Download HTML report", report_html, file_name="security_report.html",
                   mime="text/html", type="primary")

st.divider()

# --- Category breakdown ----------------------------------------------------
st.header("Findings by category")
real_df = df[df["Verdict"] == "REAL"]
if len(real_df):
    counts = real_df["Category"].value_counts()
    fig = go.Figure(go.Bar(
        x=counts.values, y=counts.index, orientation="h",
        marker_color=GREEN, text=counts.values, textposition="outside"))
    fig.update_layout(
        template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#c9d1d9", family="JetBrains Mono"),
        height=300, margin=dict(l=10, r=10, t=10, b=10),
        xaxis_title="Real findings")
    st.plotly_chart(fig, use_container_width=True)
else:
    st.caption("No real findings to break down.")

st.divider()

# --- Per-finding explainability -------------------------------------------
st.header("Why the model flagged it")
if len(real_df):
    idx_options = real_df.index.tolist()
    def _fmt(i):
        r = df.loc[i]
        return f"{r['Vulnerability']}  ·  {r['URL'][-45:]}"
    chosen = st.selectbox("Confirmed finding", idx_options, format_func=_fmt)
    row = df.loc[chosen]
    c1, c2 = st.columns([1, 2])
    c1.metric("Verdict", row["Verdict"])
    c1.metric("Confidence", f"{row['Confidence']:.0%}")
    c1.metric("Category", row["Category"])
    try:
        import shap
        explainer = shap.TreeExplainer(model)
        sv = explainer.shap_values(X.loc[[chosen]])
        vals = sv[0] if not hasattr(sv[0], "__len__") else (sv[1][0] if isinstance(sv, list) else sv[0])
        contrib = pd.Series(vals, index=FEATURE_COLUMNS).sort_values()
        fig2 = go.Figure(go.Bar(
            x=contrib.values, y=contrib.index, orientation="h",
            marker_color=[RED if v > 0 else CYAN for v in contrib.values]))
        fig2.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#c9d1d9", family="JetBrains Mono"),
            height=300, margin=dict(l=10, r=10, t=10, b=10),
            xaxis_title="SHAP contribution (→ real finding)")
        c2.plotly_chart(fig2, use_container_width=True)
    except Exception as exc:
        c2.caption(f"SHAP unavailable ({exc}); feature values:")
        c2.dataframe(X.loc[[chosen]].T, use_container_width=True)
else:
    st.caption("No confirmed finding to explain.")

st.divider()

# --- Payloads --------------------------------------------------------------
st.header("Re-verification payloads")
vulns = sorted({v for v in real_df["Vulnerability"].unique() if suggest(v)})
if vulns:
    v = st.selectbox("Confirmed vulnerability", vulns)
    for technique, items in suggest(v).items():
        st.subheader(technique)
        for it in items:
            color = {"high": RED, "medium": AMBER, "low": MUTED}.get(it["risk"], MUTED)
            st.code(it["payload"], language="text")
            st.markdown(f"<span style='color:{color}'>● {it['risk'].upper()}</span> — {it['note']}", unsafe_allow_html=True)
else:
    st.caption("No confirmed finding has a payload template yet.")

st.divider()

# --- Held-out performance --------------------------------------------------
st.header("Model performance (held-out test set)")
m = load_metrics()
if m:
    p = st.columns(4)
    p[0].metric("Precision", f"{m.get('precision', 0):.0%}")
    p[1].metric("Recall", f"{m.get('recall', 0):.0%}")
    p[2].metric("F1", f"{m.get('f1', 0):.0%}")
    p[3].metric("PR-AUC", f"{m.get('pr_auc', 0):.3f}")
figs = [("model_vs_zap.png", "Triage value"), ("confusion_matrix.png", "Confusion matrix"),
        ("per_category.png", "Recall by category"), ("shap_summary.png", "Global feature impact")]
cols = st.columns(2)
for i, (fname, cap) in enumerate(figs):
    fp = config.ROOT_DIR / "docs" / fname
    if fp.exists():
        cols[i % 2].image(str(fp), caption=cap, use_container_width=True)
st.caption("Results on a held-out split never seen in training. The task is highly "
           "separable; the value is automated, explainable triage — see the README.")
