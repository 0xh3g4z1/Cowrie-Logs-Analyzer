# Cowrie Log Analyzer

A local Streamlit dashboard for exploring Cowrie JSON event logs. It summarizes
threat activity and supports filtering, source-IP investigation, authentication
and command analysis, attacker-session reconstruction, file/hash review, and
raw event inspection. Individual events can be removed from their source log.

## Requirements

- Python 3.12
- Cowrie JSON logs (`.json`, `.jsonl`, or `.log`), optionally gzip-compressed

## Run locally

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run main.py
```

Open the local URL printed by Streamlit. The app initially scans the project
folder recursively; use the sidebar to select a different folder.

## Log data

Keep your log files in `data/` or another local folder. Log data is excluded
from Git because it can contain sensitive IP addresses, credentials, and
attacker activity. Do not commit real or sensitive logs to a public repository.

Deleting an event permanently removes its JSON line from the source log. Back up
the log first if you need to preserve the original data.

## GitHub Actions

The CI workflow installs the declared dependencies and checks that `main.py`
compiles with Python 3.12.