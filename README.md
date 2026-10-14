# Cowrie Log Analyzer

A local Streamlit dashboard for exploring Cowrie JSON event logs. It summarizes
threat activity and supports filtering, source-IP investigation, authentication
and command analysis, attacker-session reconstruction, file/hash review, and
raw event inspection. Individual events can be removed from their source log.

## Features

- Recursive scanning of local Cowrie log folders and support for `.json`,
  `.jsonl`, `.log`, and gzip-compressed log files
- Sidebar filters for event type, source IP, full-text search, and date range
- Threat activity overview with event counts, source-IP summaries, command totals,
  and login outcomes
- Source IP investigation with per-IP event breakdowns and direct IP lookups
- Authentication analysis for failed and successful login attempts, including
  most-used usernames and passwords
- Command investigation with searchable command inputs, occurrence summaries,
  and event details showing UTC time, source IP, session, source port, and the
  full command
- Session reconstruction to inspect all events tied to a specific attacker
  session ID
- File activity tracking for uploads/downloads, output file names, and observed
  SHA hashes
- Cowrie lib directory review for SSH keys, UUIDs, and downloaded artifacts
  stored under a local `data/lib/` folder;
- Artifact inspection for selected lib files, including text preview or hex dump
  fallback for binary content
- Raw event browser for viewing the original JSON payload for any selected event
- Optional permanent removal of a selected event from its source log after user
  confirmation

## Requirements

- Python 3.12
- Cowrie JSON logs (`.json`, `.jsonl`, or `.log`), optionally gzip-compressed

## Run locally

### Linux

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run main.py
```

### Windows (PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run main.py
```

Open the local URL printed by Streamlit. The app initially scans the `data/`
folder recursively; use the sidebar to select a different folder.

## Data layout

Cowrie data can be organized like this:

```text
data/
├── lib/
│   ├── downloads/
│   ├── ssh_host_rsa_key
│   ├── uuid
│   └── tty/                 # excluded from artifact analysis
└── logs/
    ├── cowrie.json
    └── cowrie.json.2026-10-09
```

The analyzer reads JSON event files from `data/logs/` and inventories files in
`data/lib/` for SSH keys, UUIDs, and downloaded artifacts.

## Log data

Keep your log files in `data/logs/` or another local folder. If your Cowrie
install includes a `data/lib/` directory, the app will also inventory that
folder and surface its SSH keys, UUID, and downloaded artifacts for review.

Log data is excluded from Git because it can contain sensitive IP addresses,
credentials, and attacker activity. Do not commit real or sensitive logs to a
public repository.

Deleting an event permanently removes its JSON line from the source log. Back up
the log first if you need to preserve the original data.

## GitHub Actions

The CI workflow installs the declared dependencies and checks that `main.py`
compiles with Python 3.12.

## Contributing

Contributions are welcome for bug fixes, usability improvements, analysis
features, and documentation updates.

1. Fork the repository and create a feature branch.
2. Keep changes focused and easy to review.
3. Run the app locally to verify behavior before submitting a pull request.
4. Update documentation when behavior or setup changes.
5. Open a pull request with a clear description of the problem and the fix.

Please avoid committing real Cowrie log data or any sensitive telemetry to the
repository.

## License

This project is licensed under the MIT License. See the LICENSE file in this
repository for the full text.

The project is provided as-is for local analysis and research use, and it is
intended to help inspect Cowrie telemetry responsibly and securely.