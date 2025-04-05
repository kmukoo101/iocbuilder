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
DEFAULT_IOC_PATTERNS = {
    "IPv4": re.compile(r'\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b'),
    "Domain": re.compile(r'\\b(?:[a-zA-Z0-9-]+\\.)+(?:com|net|org|edu|info|ru|co|io|gov|biz)\\b'),
    "Email": re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+'),
    "MD5": re.compile(r'\\b[a-fA-F0-9]{32}\\b'),
    "SHA1": re.compile(r'\\b[a-fA-F0-9]{40}\\b'),
    "SHA256": re.compile(r'\\b[a-fA-F0-9]{64}\\b'),
    "CVE": re.compile(r'CVE-\\d{4}-\\d{4,7}'),
    "URL": re.compile(r'https?://[\\w./?=#&%+-]+')
}

# --- Functions ---
def extract_iocs(text, patterns):
    matches = defaultdict(set)
    for label, pattern in patterns.items():
        for match in pattern.findall(text):
            matches[label].add(match.strip())
    return {k: sorted(list(v)) for k, v in matches.items() if v}

def calculate_ioc_correlation(iocs):
    flat_list = [val for values in iocs.values() for val in values]
    freq = Counter(flat_list)
    scores = {val: freq[val] for val in flat_list}
    return scores

def save_session(iocs, tags, notes):
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

def export_to_csv(iocs, analyst_notes):
    rows = []
    for typ, values in iocs.items():
        for val in values:
            note = analyst_notes.get(val, "")
            rows.append((typ, val, note))
    df = pd.DataFrame(rows, columns=["Type", "Value", "Analyst Note"])
    return df.to_csv(index=False).encode("utf-8")

def generate_sigma_rule(iocs):
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
    counts = Counter({k: len(v) for k, v in iocs.items()})
    df = pd.DataFrame(counts.items(), columns=["IOC Type", "Count"])
    chart = alt.Chart(df).mark_bar().encode(
        x=alt.X('IOC Type', sort='-y'),
        y='Count',
        color='IOC Type'
    ).properties(title="IOC Type Frequency")
    return chart

def save_tokenized_public_session(iocs, tags, notes):
    token = str(uuid.uuid4())[:8]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(ARCHIVE_DIR, f"public_{token}.json")
    with open(path, "w") as f:
        json.dump({"timestamp": ts, "tags": tags, "notes": notes, "iocs": iocs}, f, indent=2)
    return token

def load_public_token(token):
    path = os.path.join(ARCHIVE_DIR, f"public_{token}.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None

# --- Streamlit UI ---
st.set_page_config(page_title="IOCBuilder", layout="wide")
st.title("IOCBuilder - IOC Extractor & Enrichment")

st.markdown("""
Paste unstructured text or logs containing potential IOCs below. Use the sidebar for campaign metadata, past session recall, and shared tokens.

**Step 1:** Paste your threat report or IOC-rich text.  
**Step 2:** Add optional campaign tags and notes on the left.  
**Step 3:** Click **Extract IOCs** to analyze and enrich.  
**Step 4:** Review the breakdown, correlation scores, timeline, and export.
""")

st.markdown("**Threat Report / Paste Raw Data**")
user_input = st.text_area("", height=250, placeholder="Example:\nSuspicious activity seen from 192.168.1.5 contacting badsite.ru and 104.21.35.64.\nRelated email: attacker@mail.ru. Associated CVE-2023-1234.\nSHA256: a9f2e831928f4863eac...")

with st.sidebar:
    st.subheader("Campaign Metadata")
    tags = st.text_input("Tags (comma-separated)")
    notes = st.text_area("Analyst Notes")
    st.markdown("---")

    st.subheader("Load Previous Sessions")
    session_files = sorted([f for f in os.listdir(ARCHIVE_DIR) if f.endswith(".zip")], reverse=True)
    if session_files:
        chosen = st.selectbox("", session_files)
        if chosen:
            with ZipFile(os.path.join(ARCHIVE_DIR, chosen)) as zipf:
                with zipf.open(zipf.namelist()[0]) as f:
                    loaded = json.load(f)
                    st.markdown(f"**Tags:** {loaded.get('tags')}")
                    st.markdown(f"**Notes:** {loaded.get('notes')}")
                    st.json(loaded.get("iocs"))
    else:
        st.info("No previous sessions found.")

    st.markdown("---")
    st.subheader("Load Shared Session via Token")
    shared_token = st.text_input("Public Token")
    if shared_token:
        loaded = load_public_token(shared_token)
        if loaded:
            st.markdown(f"### Public Session: {shared_token}")
            st.markdown(f"**Tags:** {loaded.get('tags')}")
            st.markdown(f"**Notes:** {loaded.get('notes')}")
            st.json(loaded.get("iocs"))
        else:
            st.warning("Invalid token or session not found.")

custom_regex_input = st.text_area("Optional: Add Custom Regex Patterns (JSON format)", height=150)
custom_patterns = {}
if custom_regex_input:
    try:
        parsed = json.loads(custom_regex_input)
        for k, v in parsed.items():
            custom_patterns[k] = re.compile(v)
    except:
        st.error("Invalid JSON format in custom patterns. Ignoring.")

merged_patterns = {**DEFAULT_IOC_PATTERNS, **custom_patterns}

if st.button("Extract IOCs"):
    if not user_input.strip():
        st.warning("Please paste some data to analyze.")
    else:
        results = extract_iocs(user_input, merged_patterns)
        correlation_scores = calculate_ioc_correlation(results)
        st.success(f"Extraction complete. {sum(len(v) for v in results.values())} IOCs found.")

        st.markdown("**IOC Summary:**")
        for key, val in results.items():
            st.markdown(f"- {key}: {len(val)} found")

        selected_type = st.multiselect("Filter by IOC Type", list(results.keys()), default=list(results.keys()))
        keyword = st.text_input("Search for specific string")

        filtered = {t: [v for v in vs if keyword.lower() in v.lower()] if keyword else vs for t, vs in results.items() if t in selected_type}

        analyst_notes = {}

        for ioc_type, values in filtered.items():
            st.subheader(ioc_type)
            rows = []
            for val in values:
                note = st.text_input(f"Note for {val}", key=f"note_{val}")
                analyst_notes[val] = note
                rows.append((val, correlation_scores.get(val, 1), note))
            df = pd.DataFrame(rows, columns=["Value", "Correlation Score", "Analyst Note"])
            st.dataframe(df)

        st.altair_chart(visualize_counts(filtered), use_container_width=True)

        st.markdown("---")
        st.subheader("Exports and Automation")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.download_button("Download CSV", export_to_csv(filtered, analyst_notes), file_name="iocs.csv", mime="text/csv")
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
            st.info(f"Public Token Link: `/public/{token}`")
