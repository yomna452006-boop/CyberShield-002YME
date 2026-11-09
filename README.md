# CyberShield v2

Defensive security event analytics prototype using Python, Streamlit, Pandas and Plotly.

## What's new in v2
- Correlates failed-login events per source IP over a configurable rolling time window.
- Explains why an event received its risk score.
- Uses a dark navy and gold interface with dark-themed charts.
- Supports CSV upload and downloadable reports.

## Deploy
Upload `app.py`, `requirements.txt`, and `README.md` to the root of your existing GitHub repository. Streamlit Community Cloud will redeploy when the repository changes.

## CSV columns
Required: `timestamp`, `source_ip`, `event_type`
Optional: `failed_logins`, `bytes_out`, `destination_port`

## Scope
Educational defensive prototype. It analyses records provided to it; it does not scan networks, intercept traffic, block systems, or perform automated response. Risk labels are triage hints, not proof of malicious activity.
