import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

st.set_page_config(page_title="CyberShield", page_icon="🛡️", layout="wide")

# -------------------- VISUAL IDENTITY --------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Playfair+Display:wght@500;600;700&display=swap');
:root { color-scheme: dark; }
.stApp { background:#0b111b; color:#f3f1eb; }
[data-testid="stHeader"] { background:rgba(11,17,27,.96); }
[data-testid="stSidebar"] { background:#101925; border-right:1px solid rgba(201,169,106,.22); }
h1,h2,h3 { font-family:'Playfair Display',Georgia,serif !important; color:#f3f1eb !important; }
p, label, span, div { }
[data-testid="stMetric"] { background:#121d2b; border:1px solid rgba(201,169,106,.28); padding:16px; border-radius:12px; }
[data-testid="stMetricLabel"] p { color:#c4ccd6 !important; font-size:14px !important; }
[data-testid="stMetricValue"] { color:#f5f1e8 !important; }
[data-testid="stDataFrame"] { border:1px solid rgba(201,169,106,.2); border-radius:10px; }
div.stButton > button, div.stDownloadButton > button { background:#c9a96a; color:#101722; border:0; border-radius:7px; font-weight:700; }
div.stButton > button:hover, div.stDownloadButton > button:hover { background:#e0c38c; color:#101722; }
div[data-testid="stAlert"] { border-radius:10px; }
.small-muted { color:#aab5c2; font-size:.9rem; }
.gold { color:#c9a96a; }
</style>
""", unsafe_allow_html=True)

# -------------------- SAMPLE DATA --------------------
SAMPLE = pd.DataFrame([
    ["2026-11-08 09:00:00","192.168.1.10","login_success",0,1200,443],
    ["2026-11-08 09:02:00","192.168.1.15","login_failed",1,500,443],
    ["2026-11-08 09:03:00","192.168.1.15","login_failed",1,500,443],
    ["2026-11-08 09:04:00","192.168.1.15","login_failed",1,500,443],
    ["2026-11-08 09:05:00","192.168.1.15","login_failed",1,500,443],
    ["2026-11-08 09:10:00","192.168.1.22","data_transfer",0,8500000,443],
    ["2026-11-08 09:12:00","192.168.1.30","port_connection",0,800,3389],
    ["2026-11-08 09:15:00","192.168.1.10","login_success",0,1000,443],
    ["2026-11-08 09:17:00","192.168.1.42","dns_request",0,300,53],
], columns=["timestamp","source_ip","event_type","failed_logins","bytes_out","destination_port"])

REQUIRED = ["timestamp","source_ip","event_type"]
OPTIONAL = ["failed_logins","bytes_out","destination_port"]

def analyse_events(frame, window_minutes=10):
    df = frame.copy()
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(missing))
    for col in OPTIONAL:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if df["timestamp"].isna().any():
        raise ValueError("Some timestamp values could not be read. Use a date/time such as 2026-11-08 09:00:00.")
    df["source_ip"] = df["source_ip"].fillna("Unknown").astype(str)
    df["event_type"] = df["event_type"].fillna("unknown").astype(str).str.lower().str.strip()
    df = df.sort_values("timestamp").reset_index(drop=True)

    # Count failed-login events per source IP in a rolling time window.
    failed_mask = df["event_type"].str.contains("failed", na=False)
    df["failed_attempts_window"] = 0
    for ip, indices in df.groupby("source_ip").groups.items():
        ip_rows = df.loc[list(indices)].sort_values("timestamp")
        failed_times = ip_rows.loc[
            ip_rows["event_type"].str.contains("failed", na=False), "timestamp"
        ].tolist()
        for idx, row in ip_rows.iterrows():
            start = row["timestamp"] - pd.Timedelta(minutes=window_minutes)
            count = sum(start <= t <= row["timestamp"] for t in failed_times)
            df.loc[idx, "failed_attempts_window"] = count

    scores, reasons = [], []
    for _, row in df.iterrows():
        score, why = 0, []
        attempts = int(row["failed_attempts_window"])
        if attempts >= 5:
            score += 60
            why.append(f"{attempts} failed-login events from this source within {window_minutes} minutes")
        elif attempts >= 3:
            score += 35
            why.append(f"{attempts} failed-login events from this source within {window_minutes} minutes")
        elif attempts == 2:
            score += 15
            why.append("Repeated failed-login activity")
        if row["bytes_out"] >= 5_000_000:
            score += 35
            why.append("Large outbound data volume (at least 5 MB)")
        elif row["bytes_out"] >= 1_000_000:
            score += 20
            why.append("Elevated outbound data volume (at least 1 MB)")
        port = int(row["destination_port"])
        if port in [23, 3389, 4444]:
            score += 15
            why.append(f"Destination port {port} requires contextual review")
        if "failed" in row["event_type"] and attempts < 2:
            score += 5
            why.append("Failed action recorded")
        score = min(score, 100)
        level = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
        scores.append(score)
        reasons.append("; ".join(why) if why else "No configured rule triggered")
    df["risk_score"] = scores
    df["risk_level"] = ["High" if x >= 60 else "Medium" if x >= 30 else "Low" for x in scores]
    df["reason"] = reasons
    return df

def make_chart(data):
    order = ["High","Medium","Low"]
    counts = data["risk_level"].value_counts().reindex(order, fill_value=0).reset_index()
    counts.columns = ["Risk level","Events"]
    fig = px.bar(counts, x="Risk level", y="Events", color="Risk level",
                 color_discrete_map={"High":"#d46a6a","Medium":"#d4ad62","Low":"#6fa88b"},
                 category_orders={"Risk level":order}, text="Events")
    fig.update_layout(
        paper_bgcolor="#0b111b", plot_bgcolor="#0b111b",
        font_color="#e9edf2", showlegend=False,
        margin=dict(l=12,r=12,t=15,b=12), height=300,
        xaxis=dict(showgrid=False, title="", tickfont=dict(color="#d4dbe4")),
        yaxis=dict(showgrid=True, gridcolor="rgba(220,230,240,.12)", title="", rangemode="tozero")
    )
    fig.update_traces(textposition="outside")
    return fig

# -------------------- NAVIGATION / INPUT --------------------
st.sidebar.markdown("# 🛡️ CyberShield")
st.sidebar.caption("INTELLIGENT INTEGRATED CYBER DEFENSE SYSTEM")
page = st.sidebar.radio("Navigation", ["Overview","Event Analysis","Risk Report","About"])
st.sidebar.divider()
st.sidebar.markdown("### Analysis settings")
window = st.sidebar.selectbox("Failed-login correlation window", [5,10,15,30], index=1)
choice = st.sidebar.radio("Data source", ["Built-in sample","Upload CSV"])
upload = st.sidebar.file_uploader("Upload security event CSV", type=["csv"]) if choice == "Upload CSV" else None
st.sidebar.caption("Required columns: timestamp, source_ip, event_type. Optional: failed_logins, bytes_out, destination_port.")
if st.sidebar.button("Analyse events", use_container_width=True):
    try:
        if choice == "Upload CSV":
            if upload is None:
                st.sidebar.warning("Upload a CSV file first.")
            else:
                st.session_state["cyber_data"] = analyse_events(pd.read_csv(upload), window)
                st.sidebar.success("Analysis completed.")
        else:
            st.session_state["cyber_data"] = analyse_events(SAMPLE, window)
            st.sidebar.success("Sample analysis completed.")
    except Exception as exc:
        st.sidebar.error(str(exc))

if "cyber_data" not in st.session_state:
    st.session_state["cyber_data"] = analyse_events(SAMPLE, window)

data = st.session_state["cyber_data"]
counts = data["risk_level"].value_counts()
high, medium, low = [int(counts.get(x,0)) for x in ["High","Medium","Low"]]

st.title("CyberShield")
st.markdown("<p class='small-muted'>Intelligent Integrated Cyber Defense System · Security Event Monitoring & Risk Assessment</p>", unsafe_allow_html=True)

if page == "Overview":
    st.subheader("Security posture at a glance")
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Events analysed",len(data))
    c2.metric("High risk",high)
    c3.metric("Medium risk",medium)
    c4.metric("Low risk",low)
    st.markdown("#### Risk distribution")
    st.plotly_chart(make_chart(data), use_container_width=True, config={"displayModeBar":False})
    st.markdown("#### Recent events")
    st.dataframe(data[["timestamp","source_ip","event_type","failed_attempts_window","risk_level","risk_score"]].tail(10),
                 use_container_width=True, hide_index=True)
    st.info(f"Failed-login events are correlated per source IP across a rolling {window}-minute window. Risk labels support analyst prioritisation; they do not prove an attack.")

elif page == "Event Analysis":
    st.subheader("Event analysis")
    selected_levels = st.multiselect("Filter by risk level",["High","Medium","Low"],default=["High","Medium","Low"])
    filtered = data[data["risk_level"].isin(selected_levels)]
    st.dataframe(filtered,use_container_width=True,hide_index=True)
    st.markdown("#### Explain an event")
    if not filtered.empty:
        selected = st.selectbox("Select source IP",filtered["source_ip"].drop_duplicates().tolist())
        rows = filtered[filtered["source_ip"]==selected]
        for _,row in rows.iterrows():
            st.markdown(f"**{row['risk_level']} risk · {row['risk_score']}/100 · {row['event_type']}**")
            st.write(row["reason"])
    else:
        st.write("No events match the selected filters.")

elif page == "Risk Report":
    st.subheader("Risk assessment report")
    st.write("Generated:",datetime.now().strftime("%Y-%m-%d %H:%M"))
    st.write(f"Events reviewed: **{len(data)}** · High: **{high}** · Medium: **{medium}** · Low: **{low}**")
    high_rows = data[data["risk_level"]=="High"]
    if high_rows.empty:
        st.success("No High-risk events were flagged by the current rules.")
    else:
        st.warning("High-risk events require analyst review.")
        st.dataframe(high_rows[["timestamp","source_ip","event_type","risk_score","reason"]],
                     use_container_width=True,hide_index=True)
    st.download_button("Download analysed report (CSV)",data.to_csv(index=False).encode("utf-8"),
                       "cybershield_risk_report.csv","text/csv")

else:
    st.subheader("About this prototype")
    st.markdown("""
**CyberShield — Intelligent Integrated Cyber Defense System**

This version demonstrates a defensive workflow:
1. Ingest security event records from a sample dataset or a user-provided CSV.
2. Correlate failed-login events from the same source IP over a configurable time window.
3. Apply transparent rules to identify events that may need attention.
4. Assign Low, Medium, or High risk levels with an explainable score.
5. Review findings and export a report.

**Current limitations:** this educational prototype analyses supplied records only. It does not perform live network monitoring, scan systems, block traffic, or take automated response actions. Thresholds are illustrative and should be validated against representative data. A flagged event is not necessarily malicious.

**Next development:** richer log parsing, baseline behaviour analysis, evaluated machine-learning models, and analyst feedback.
""")

st.divider()
st.caption("CYBERSHIELD · DEFENSIVE SECURITY ANALYTICS · EDUCATIONAL PROTOTYPE")
