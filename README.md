# Network Security Monitoring Dashboard

A Windows-friendly Python + Flask learning project that summarizes offline network-traffic records and highlights simple patterns for analyst review.

## Features

- Traffic event count, byte totals, and average record size
- Protocol distribution
- Frequent source and destination summaries
- Simple unusual-record indicators
- Interactive dashboard with event table
- Export findings as JSON and CSV
- Included synthetic sample dataset

## Safety and scope

This project analyzes CSV records only. It does not capture live packets, scan hosts, probe ports, or attempt to access systems. Use synthetic data or logs you are authorized to review, and remove personal or confidential information before uploading data. A `REVIEW` label is only a heuristic indicator; it does not prove malicious activity.

## Windows installation

1. Install Python 3.10+ from https://www.python.org/downloads/.
2. Extract this ZIP file.
3. Open PowerShell in the extracted folder.
4. Create a virtual environment:

   ```powershell
   py -m venv .venv
   ```

5. Activate it:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

   If activation is blocked, use Command Prompt:

   ```cmd
   .venv\Scripts\activate.bat
   ```

6. Install the dependency:

   ```powershell
   py -m pip install -r requirements.txt
   ```

7. Run the dashboard:

   ```powershell
   py app.py
   ```

8. Open `http://127.0.0.1:5001`.

Click **Analyze included sample traffic** to try the sample, or upload a CSV with the required columns.

## CSV format

Required headers:

```csv
timestamp,source,destination,protocol,bytes
2026-10-01 09:00:00,192.0.2.10,198.51.100.20,HTTPS,1400
```

Use documentation-only IP ranges (such as 192.0.2.0/24 and 198.51.100.0/24) in sample data. `bytes` must be a non-negative integer.

## Project structure

```text
Network_Security_Monitoring_Dashboard/
├── app.py
├── monitor.py
├── requirements.txt
├── README.md
├── .gitignore
├── data/
│   └── sample_network_traffic.csv
├── templates/
│   ├── index.html
│   └── dashboard.html
└── static/
    └── style.css
```

## GitHub upload

1. Create a new public repository named `Network-Security-Monitoring-Dashboard`.
2. Extract the ZIP.
3. Upload the project files and folders (not the ZIP itself).
4. Commit with message: `Initial commit - Network Security Monitoring Dashboard`.

Or use Git for Windows in PowerShell:

```powershell
git init
git add .
git commit -m "Initial commit - Network Security Monitoring Dashboard"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/Network-Security-Monitoring-Dashboard.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username.

## Suggested repository description

Python Flask dashboard for offline network traffic analysis, protocol statistics, unusual activity indicators, and downloadable monitoring reports.

## Suggested topics

`cybersecurity` `network-security` `network-monitoring` `python` `flask` `traffic-analysis` `blue-team`
