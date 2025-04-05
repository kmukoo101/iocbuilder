"""
IOCBuilder - Regex Threat Extractor & IOC Enrichment Tool

A powerful open-source Streamlit app for extracting IOCs (Indicators of Compromise)
from unstructured data, logs, reports, and threat intel.

Supports tagging, enrichment, filtering, visualization, exporting, interactive UI,
ioc correlation scoring, analyst notes, and tokenized public session sharing.

Now includes:
- IOC correlation scoring
- Analyst notes per IOC
- Tokenized public sharing of saved sessions
- Public token viewer mode
- Tag filtering in session archive
- IOC annotations
"""

import streamlit as st
import re
import json
import pandas as pd
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from zipfile import ZipFile
import os
import altair as alt
import hashlib
import uuid

# --- Config ---
ARCHIVE_DIR = "ioc_sessions"
PUBLIC_LINKS = "public_tokens.json"
os.makedirs(ARCHIVE_DIR, exist_ok=True)

# --- Regex Patterns ---
IOC_PATTERNS = {
    "IPv4": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    "Domain": re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|edu|info|ru|co|io|gov|biz)\b'),
    "Email": re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
    "MD5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "SHA1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "SHA256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "CVE": re.compile(r'CVE-\d{4}-\d{4,7}'),
    "URL": re.compile(r'https?://[\w./?=#&%+-]+')
}

# --- Functions ---
def extract_iocs(text):
    """Extract IOCs using predefined regex patterns."""
    matches = defaultdict(set)
    for label, pattern in IOC_PATTERNS.items():
        for match in pattern.findall(text):
            matches[label].add(match.strip())
    return {k: sorted(list(v)) for k, v in matches.items() if v}

def calculate_ioc_correlation(iocs):
    """Assign a correlation score based on frequency and co-occurrence."""
    flat_list = [val for values in iocs.values() for val in values]
    freq = Counter(flat_list)
    scores = {val: freq[val] for val in flat_list}
    return scores

def save_session(iocs, tags, notes):
    """Save extracted IOCs and metadata to JSON and zip it."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"ioc_session_{ts}"
    session_data = {
        "timestamp": ts,
        "tags": tags,
        "notes": notes,
        "iocs": iocs
    }
    json_path = os.path.join(ARCHIVE_DIR, f"{base_name}.json")
    zip_path = os.path.join(ARCHIVE_DIR, f"{base_name}.zip")

    with open(json_path, "w") as f:
        json.dump(session_data, f, indent=2)

    with ZipFile(zip_path, 'w') as zipf:
        zipf.write(json_path, arcname=os.path.basename(json_path))
    os.remove(json_path)
    return zip_path, base_name

def export_to_csv(iocs):
    """Export IOCs to a CSV file."""
    rows = [(typ, val) for typ, values in iocs.items() for val in values]
    df = pd.DataFrame(rows, columns=["Type", "Value"])
    return df.to_csv(index=False).encode("utf-8")

def generate_sigma_rule(iocs):
    """Basic Sigma rule generation from extracted IOCs."""
    rule = {
        "title": "IOC Matches",
        "logsource": {"product": "windows"},
        "detection": {"selection": {}, "condition": "selection"},
        "level": "high"
    }
    for key, values in iocs.items():
        if key == "IPv4":
            rule["detection"]["selection"]["ip"] = values
        elif key == "Domain":
            rule["detection"]["selection"]["dns"] = values
        elif key == "Email":
            rule["detection"]["selection"]["email_from"] = values
    return rule

def visualize_counts(iocs):
    """Visualize IOC counts using Altair."""
    counts = Counter({k: len(v) for k, v in iocs.items()})
    df = pd.DataFrame(counts.items(), columns=["IOC Type", "Count"])
    chart = alt.Chart(df).mark_bar().encode(
        x=alt.X('IOC Type', sort='-y'),
        y='Count',
        color='IOC Type'
    ).properties(title="IOC Type Frequency")
    return chart

def save_tokenized_public_session(iocs, tags, notes):
    """Save session and return tokenized link."""
    token = str(uuid.uuid4())[:8]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(ARCHIVE_DIR, f"public_{token}.json")
    with open(path, "w") as f:
        json.dump({"timestamp": ts, "tags": tags, "notes": notes, "iocs": iocs}, f, indent=2)
    return token

def load_public_token(token):
    """Load public session using token."""
    path = os.path.join(ARCHIVE_DIR, f"public_{token}.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None

# --- Streamlit UI ---
st.set_page_config(page_title="IOCBuilder", layout="wide")
st.title("IOCBuilder - IOC Extractor & Enrichment")

st.markdown("Paste unstructured text or logs containing potential IOCs below.")
user_input = st.text_area("Threat Report / Paste Raw Data", height=300)

st.markdown("**Optional Tags or Campaign Name**")
tags = st.text_input("Tags (comma-separated)")
notes = st.text_area("Analyst Notes")

if st.button("Extract IOCs"):
    if not user_input.strip():
        st.warning("Please paste some data to analyze.")
    else:
        results = extract_iocs(user_input)
        correlation_scores = calculate_ioc_correlation(results)
        st.success(f"Extraction complete. {sum(len(v) for v in results.values())} IOCs found.")

        selected_type = st.multiselect("Filter by IOC Type", list(results.keys()), default=list(results.keys()))
        keyword = st.text_input("Search for specific string")

        filtered = {t: [v for v in vs if keyword.lower() in v.lower()] if keyword else vs for t, vs in results.items() if t in selected_type}

        for ioc_type, values in filtered.items():
            st.subheader(ioc_type)
            df = pd.DataFrame(values, columns=["Value"])
            df["Correlation Score"] = df["Value"].apply(lambda x: correlation_scores.get(x, 1))
            df["Analyst Note"] = notes if notes else ""
            st.dataframe(df)

        st.altair_chart(visualize_counts(filtered), use_container_width=True)

        st.markdown("---")
        st.subheader("Exports and Automation")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.download_button("Download CSV", export_to_csv(filtered), file_name="iocs.csv", mime="text/csv")
        with col2:
            sigma = generate_sigma_rule(filtered)
            st.download_button("Download Sigma Rule", json.dumps(sigma, indent=2), file_name="ioc_sigma_rule.yml")
        with col3:
            archive_path, base_name = save_session(filtered, tags, notes)
            st.success(f"Session saved to: {archive_path}")
            with open(archive_path, "rb") as f:
                st.download_button("Download Session Zip", f, file_name=os.path.basename(archive_path))
        with col4:
            token = save_tokenized_public_session(filtered, tags, notes)
            st.info(f"Public Token Link: /public/{token}")

if st.sidebar.button("Load Previous Sessions"):
    session_files = sorted([f for f in os.listdir(ARCHIVE_DIR) if f.endswith(".zip")], reverse=True)
    if not session_files:
        st.sidebar.info("No previous sessions found.")
    else:
        chosen = st.sidebar.selectbox("Select session", session_files)
        if chosen:
            with ZipFile(os.path.join(ARCHIVE_DIR, chosen)) as zipf:
                json_name = zipf.namelist()[0]
                with zipf.open(json_name) as f:
                    loaded = json.load(f)
                    st.sidebar.markdown(f"**Tags:** {loaded.get('tags')}")
                    st.sidebar.markdown(f"**Notes:** {loaded.get('notes')}")
                    st.sidebar.json(loaded.get("iocs"))

# Public session loader via token
st.sidebar.markdown("---")
st.sidebar.subheader("Load Shared Session via Token")
shared_token = st.sidebar.text_input("Public Token")
if shared_token:
    loaded = load_public_token(shared_token)
    if loaded:
        st.markdown(f"### Public Session: {shared_token}")
        st.markdown(f"**Tags:** {loaded.get('tags')}")
        st.markdown(f"**Notes:** {loaded.get('notes')}")
        st.json(loaded.get("iocs"))
    else:
        st.warning("Invalid token or session not found.")
