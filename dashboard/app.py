from __future__ import annotations

from datetime import datetime, timedelta
from html import escape
from pathlib import Path
import sys

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dns_filter import DNSFilter, load_model

st.set_page_config(
    page_title="Aegis DNS | Privacy Filter",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_resource
def get_model():
    artifact = ROOT / "models" / "domain_model.joblib"
    if artifact.exists():
        return load_model(artifact)
    return None


def seed_logs() -> list[dict[str, object]]:
    now = datetime.now()
    samples = [
        ("portal.northstar.edu", "Allowed", 8, "Benign", "Campus portal"),
        ("cdn.jsdelivr.net", "Allowed", 8, "Benign", "Static assets"),
        ("secure-account-verify.top", "Blocked", 83, "Suspicious", "Credential phishing"),
        ("updates.office.com", "Allowed", 8, "Benign", "Software update"),
        ("malware.test", "Blocked", 100, "Known malicious", "Threat feed match"),
        ("video.learning.edu", "Allowed", 8, "Benign", "Learning platform"),
        ("xn--paypa1-login.click", "Blocked", 100, "Known malicious", "Lookalike / suspicious"),
        ("api.research-lab.org", "Allowed", 8, "Benign", "Research service"),
    ]
    return [
        {
            "Time": (now - timedelta(minutes=3 * i)).strftime("%H:%M:%S"),
            "Domain": domain,
            "Action": action,
            "Risk": risk,
            "Category": category,
            "Source": source,
        }
        for i, (domain, action, risk, category, source) in enumerate(samples)
    ]


def inject_styles() -> None:
    st.markdown(
        """
        <style>
        :root { --ink:#e7edf5; --muted:#8392a8; --line:#202d40; --panel:#111a28; }
        html, body, [class*="css"] { font-family:ui-sans-serif,system-ui,-apple-system,'Segoe UI',sans-serif; }
        .stApp { background:radial-gradient(ellipse at 80% 0%, #142238 0%, #0b111b 48%); color:var(--ink); }
        [data-testid="stSidebar"] { background:#0d1521; border-right:1px solid #1e2b3d; }
        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:#90a0b7; }
        .block-container { max-width:1420px; padding-top:2rem; padding-bottom:3rem; }
        h1,h2,h3 { letter-spacing:-.035em; color:#f1f5fa; }
        .eyebrow { color:#60d7b0; font:500 11px ui-monospace,SFMono-Regular,Consolas,monospace; letter-spacing:.15em; text-transform:uppercase; }
        .muted { color:#8492a7; font-size:14px; }
        .brand { display:flex; align-items:center; gap:11px; margin:4px 0 30px; }
        .brand-mark { width:36px; height:36px; border-radius:11px; background:#123c39; color:#6ce4b5; display:grid; place-items:center; font-size:20px; }
        .brand-name { color:#f0f5fb; font-weight:700; font-size:17px; }
        .brand-sub { color:#73839a; font-size:11px; margin-top:1px; }
        .status-pill { display:inline-flex; gap:8px; align-items:center; border:1px solid #23473f; background:#10251f; color:#7be4bb; border-radius:99px; padding:7px 12px; font:500 11px ui-monospace,SFMono-Regular,Consolas,monospace; }
        .status-dot { height:7px; width:7px; border-radius:50%; background:#4bd4a2; box-shadow:0 0 12px #4bd4a2; }
        .metric-card { background:linear-gradient(145deg,#141f2e,#101824); border:1px solid #202d3f; border-radius:15px; padding:19px 20px; min-height:122px; }
        .metric-label { color:#91a0b5; font-size:12px; }
        .metric-value { color:#f1f5fb; font-size:29px; font-weight:700; letter-spacing:-.05em; margin:6px 0 3px; }
        .metric-foot { color:#66dcb2; font-size:11px; }
        [data-testid="stVerticalBlockBorderWrapper"] { background:#111a28; border-color:#202d3f; border-radius:15px; }
        .section-heading { color:#eff4fa; font-size:16px; font-weight:600; }
        .section-caption { color:#8291a6; font-size:12px; margin-top:4px; }
        .log-table-wrap { overflow-x:auto; margin-top:16px; }
        .log-table { border-collapse:collapse; width:100%; min-width:640px; font-size:12px; }
        .log-table th { color:#8291a6; font-weight:500; text-align:left; padding:11px 12px; border-bottom:1px solid #263448; }
        .log-table td { color:#d5deea; padding:12px; border-bottom:1px solid #1d2939; }
        .log-table tr:last-child td { border-bottom:0; }
        .log-domain { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
        .log-allowed { color:#68deb2; } .log-blocked { color:#ff828b; }
        .stButton button[kind="primary"] { background:#43d4a0; border:0; color:#08221b; font-weight:700; border-radius:9px; }
        .stButton button[kind="primary"]:hover { background:#69e5b7; color:#08221b; }
        .stTextInput input { background:#0d1521; border-color:#2b3a4d; border-radius:9px; color:#edf4fc; }
        div[data-testid="stDataFrame"] { border:1px solid #202d3f; border-radius:12px; overflow:hidden; }
        div[data-testid="stTabs"] button { color:#98a7bb; }
        .stAlert { border-radius:10px; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar() -> str:
    with st.sidebar:
        st.markdown(
            '<div class="brand"><div class="brand-mark">◈</div><div><div class="brand-name">Aegis DNS</div><div class="brand-sub">PRIVACY FILTER · DEMO</div></div></div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div class="eyebrow">Workspace</div>', unsafe_allow_html=True)
        page = st.radio(
            "Workspace",
            ["Overview", "DNS activity", "Federated model", "Settings"],
            label_visibility="collapsed",
        )
        st.markdown("---")
        st.markdown('<div class="eyebrow">Organization node</div>', unsafe_allow_html=True)
        st.markdown("**Northstar Research**  \n`NODE · ORG-024`")
        st.markdown('<span class="status-pill"><span class="status-dot"></span> NODE CONNECTED</span>', unsafe_allow_html=True)
        st.markdown("---")
        st.caption("Local inference active · Raw DNS queries stay on this node.")
        return page


def render_header() -> None:
    left, right = st.columns([0.75, 0.25], vertical_alignment="center")
    with left:
        st.markdown('<div class="eyebrow">PRIVACY-FIRST · FEDERATED INTELLIGENCE</div>', unsafe_allow_html=True)
        st.title("DNS protection overview")
        st.markdown('<div class="muted">Monitor your organization’s DNS traffic and block suspicious domains at the edge.</div>', unsafe_allow_html=True)
    with right:
        st.markdown('<div style="text-align:right"><span class="status-pill"><span class="status-dot"></span> PROTECTION ACTIVE</span></div>', unsafe_allow_html=True)


def metric(label: str, value: str, foot: str) -> None:
    st.markdown(
        f'<div class="metric-card"><div class="metric-label">{label}</div><div class="metric-value">{value}</div><div class="metric-foot">{foot}</div></div>',
        unsafe_allow_html=True,
    )


def activity_chart() -> str:
    allowed = [44, 58, 52, 69, 61, 75, 67, 82, 72, 91, 77, 95]
    blocked = [5, 8, 6, 12, 8, 15, 11, 18, 12, 22, 16, 20]
    width, baseline, chart_height = 960, 205, 165

    def coordinates(values: list[int]) -> list[tuple[int, int]]:
        return [
            (int(index * width / (len(values) - 1)), baseline - round(value / 100 * chart_height))
            for index, value in enumerate(values)
        ]

    def point_string(points: list[tuple[int, int]]) -> str:
        return " ".join(f"{x},{y}" for x, y in points)

    allowed_points = coordinates(allowed)
    blocked_points = coordinates(blocked)
    allowed_area = (
        f"M {allowed_points[0][0]},{baseline} L {point_string(allowed_points)} "
        f"L {allowed_points[-1][0]},{baseline} Z"
    )
    grid = "".join(
        f'<line x1="0" y1="{baseline - value / 100 * chart_height:.0f}" '
        f'x2="{width}" y2="{baseline - value / 100 * chart_height:.0f}" stroke="#263448" stroke-dasharray="4 7"/>'
        for value in (25, 50, 75, 100)
    )
    labels = "".join(
        f'<text x="{index * width / 11:.0f}" y="238" text-anchor="middle" fill="#8090a6" font-size="11">{hour}</text>'
        for index, hour in enumerate(("00", "02", "04", "06", "08", "10", "12", "14", "16", "18", "20", "22"))
    )
    return (
        '<div style="display:flex;gap:18px;margin:12px 0 2px;color:#91a0b5;font-size:11px">'
        '<span><b style="color:#39c999">●</b> Allowed</span>'
        '<span><b style="color:#f06b77">●</b> Blocked</span></div>'
        '<svg role="img" aria-label="DNS requests processed during the last 24 hours" '
        'viewBox="0 0 960 250" width="100%" style="margin-top:4px">'
        f'{grid}<path d="{allowed_area}" fill="#39c999" fill-opacity=".09"/>'
        f'<polyline points="{point_string(allowed_points)}" fill="none" stroke="#39c999" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>'
        f'<polyline points="{point_string(blocked_points)}" fill="none" stroke="#f06b77" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>'
        f'{labels}</svg>'
    )


def run_domain_check(engine: DNSFilter) -> None:
    with st.form("domain_check", clear_on_submit=False):
        domain_col, button_col = st.columns([0.79, 0.21], vertical_alignment="bottom")
        with domain_col:
            domain = st.text_input("Domain to check", placeholder="e.g. secure-account-verify.top", label_visibility="collapsed")
        with button_col:
            submitted = st.form_submit_button("⌕  Check domain", type="primary", use_container_width=True)
    if submitted:
        try:
            decision = engine.evaluate(domain)
        except (ValueError, RuntimeError) as error:
            st.error(str(error))
            return
        st.session_state.logs.insert(
            0,
            {
                "Time": datetime.now().strftime("%H:%M:%S"),
                "Domain": decision.domain,
                "Action": decision.action,
                "Risk": decision.risk_score,
                "Category": decision.category,
                "Source": decision.reason,
            },
        )
        st.session_state.last_decision = decision
    decision = st.session_state.get("last_decision")
    if decision:
        if decision.action == "Blocked":
            st.error(f"⛔  {decision.domain} — blocked · risk {decision.risk_score}% · {decision.reason}")
        else:
            st.success(f"✓  {decision.domain} — allowed · risk {decision.risk_score}% · {decision.reason}")


def overview(engine: DNSFilter) -> None:
    if "logs" not in st.session_state:
        st.session_state.logs = seed_logs()
    logs = st.session_state.logs
    blocked = sum(row["Action"] == "Blocked" for row in logs)
    st.markdown("")
    cards = st.columns(4)
    with cards[0]:
        metric("DNS QUERIES TODAY", f"{1_284 + len(logs) - 8:,}", "↑ 12.8% vs. yesterday")
    with cards[1]:
        metric("THREATS BLOCKED", f"{47 + blocked - 3:,}", "↑ 8 blocked this hour")
    with cards[2]:
        metric("MODEL ACCURACY", "98.4%", "↑ 0.6% after round 24")
    with cards[3]:
        metric("FILTER LATENCY", "8.2 ms", "↓ 1.4 ms this week")
    st.markdown("")
    with st.container(border=True):
        st.markdown('<div class="section-heading">Quick domain check</div><div class="section-caption">Test a hostname against the active local filtering model.</div>', unsafe_allow_html=True)
        run_domain_check(engine)
    st.markdown("")
    chart_col, model_col = st.columns([1.55, 1], gap="large")
    with chart_col:
        with st.container(border=True):
            st.markdown('<div class="section-heading">DNS activity</div><div class="section-caption">Requests processed · last 24 hours</div>', unsafe_allow_html=True)
            st.markdown(activity_chart(), unsafe_allow_html=True)
    with model_col:
        with st.container(border=True):
            st.markdown('<div class="section-heading">Federated model</div><div class="section-caption">Shared intelligence, private local data</div>', unsafe_allow_html=True)
            st.markdown("")
            st.markdown("**Round 24**  ·  Global model v1.8.2")
            st.progress(0.984, text="Validation accuracy · 98.4%")
            st.markdown("")
            st.markdown('<div class="muted">Last sync</div><div style="color:#eaf1f8;font-size:14px;margin:4px 0 15px">Today, 09:42 AM</div>', unsafe_allow_html=True)
            st.markdown('<div class="muted">Privacy status</div><div style="color:#69dcb2;font-size:14px;margin-top:4px">●  Only model updates are shared</div>', unsafe_allow_html=True)
    st.markdown("")
    show_logs(logs[:7], compact=True)


def show_logs(logs: list[dict[str, object]], compact: bool = False) -> None:
    with st.container(border=True):
        st.markdown('<div class="section-heading">Recent filtering events</div><div class="section-caption">Local query details stay on this organization node.</div>', unsafe_allow_html=True)
        columns = ["Time", "Domain", "Action", "Risk", "Category"]
        if not compact:
            columns.append("Source")
        header = "".join(f"<th>{escape(column)}</th>" for column in columns)
        rows = []
        for log in logs:
            cells = []
            for column in columns:
                value = str(log[column])
                css_class = ""
                if column == "Domain":
                    css_class = ' class="log-domain"'
                elif column == "Action":
                    css_class = ' class="log-blocked"' if value == "Blocked" else ' class="log-allowed"'
                elif column == "Risk":
                    value += "%"
                cells.append(f"<td{css_class}>{escape(value)}</td>")
            rows.append(f"<tr>{''.join(cells)}</tr>")
        table = (
            '<div class="log-table-wrap"><table class="log-table"><thead><tr>'
            f"{header}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
        )
        st.markdown(table, unsafe_allow_html=True)


def main() -> None:
    inject_styles()
    page = render_sidebar()
    try:
        model = get_model()
        engine = DNSFilter(
            model=model,
            threshold=st.session_state.get("filter_threshold", 70),
            model_name="Federated model" if model else "Heuristic baseline",
        )
    except (RuntimeError, FileNotFoundError, TypeError) as error:
        st.error(f"Unable to load the configured model: {error}")
        st.stop()

    if page == "Overview":
        render_header()
        overview(engine)
    elif page == "DNS activity":
        st.markdown('<div class="eyebrow">LIVE MONITORING</div>', unsafe_allow_html=True)
        st.title("DNS activity")
        st.markdown('<div class="muted">Inspect recent decisions made by this organization’s local filter.</div>', unsafe_allow_html=True)
        if "logs" not in st.session_state:
            st.session_state.logs = seed_logs()
        st.markdown("")
        run_domain_check(engine)
        st.markdown("")
        all_logs = st.session_state.logs
        query = st.text_input("Filter by domain", placeholder="Search domains…")
        if query:
            all_logs = [row for row in all_logs if query.lower() in str(row["Domain"]).lower()]
        show_logs(all_logs)
    elif page == "Federated model":
        st.markdown('<div class="eyebrow">COLLABORATIVE LEARNING</div>', unsafe_allow_html=True)
        st.title("Federated model")
        st.markdown('<div class="muted">Organizations improve shared threat detection without sharing raw DNS logs.</div>', unsafe_allow_html=True)
        st.markdown("")
        stats = st.columns(3)
        with stats[0]:
            metric("GLOBAL MODEL", "v1.8.2", "Round 24 complete")
        with stats[1]:
            metric("VALIDATION ACCURACY", "98.4%", "Demo metric")
        with stats[2]:
            metric("PARTICIPATING NODES", "12", "Hospitals · schools · offices")
        st.markdown("")
        st.info("Demo mode: federated-learning metrics shown here are illustrative. This dashboard does not contact a central server or transmit query data.")
        with st.container(border=True):
            st.markdown('<div class="section-heading">How privacy is preserved</div><div class="section-caption">Inference is local. Only model updates are intended to leave the organization.</div><br><b>1 · Local filtering</b><br><span class="muted">DNS requests are scored on this node. Domain-level traffic logs are not uploaded.</span><br><br><b>2 · Federated training</b><br><span class="muted">Organizations train locally and contribute model updates to improve shared detection.</span><br><br><b>3 · Central aggregation</b><br><span class="muted">A coordinator combines updates and distributes a refreshed global model.</span>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="eyebrow">CONFIGURATION</div>', unsafe_allow_html=True)
        st.title("Filter settings")
        st.markdown('<div class="muted">Tune local blocking behavior for this demo node.</div>', unsafe_allow_html=True)
        st.markdown("")
        threshold = st.slider(
            "Block risk threshold", min_value=50, max_value=95, value=70, step=1,
            key="filter_threshold", help="Domains at or above this risk score are blocked.",
        )
        st.caption(f"Domains scoring {threshold}% or higher will be blocked.")
        st.info("The demo uses an illustrative heuristic unless a compatible model artifact is placed at `models/domain_model.joblib`.")


if __name__ == "__main__":
    main()
