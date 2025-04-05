# IOCBuilder

This regex threat extractor & IOC enrichment app is a web-based tool for extracting Indicators of Compromise (IOCs) from unstructured text such as logs, threat reports, and other raw data.

This app helps security analysts and incident responders quickly identify, enrich, filter, visualize, and export IOCs for use in detection, investigation, and intelligence operations.

## Features

- Extract IOCs using regex patterns (IPv4, Domains, Emails, Hashes, CVEs, URLs)
- Filter IOCs by type or keyword
- Add analyst notes for each IOC
- Assign automatic correlation scores
- Tag campaigns or sessions
- Visualize IOC frequency and timeline clustering
- Generate Sigma detection rules
- Export results as:
  - CSV
  - Sigma rule YAML
  - PDF report
  - Session ZIP archive
- Public session sharing via tokenized links
- Load archived or shared sessions via token
- Optional enrichment lookups for IPs, domains, hashes (free APIs only)
- Support for custom user-defined regex patterns

## Demo

Access the live public app here:  
**https://iocbuilder.streamlit.app/**

## Requirements

- Python 3.8+
- See `requirements.txt` for dependencies.

Install locally:
```bash
pip install -r requirements.txt
streamlit run iocabuilder_app.py
```

## Deployment

You can deploy this app here: [Streamlit Community Cloud](https://streamlit.io/cloud).  
Use `.streamlit/config.toml` to customize UI theme settings.

