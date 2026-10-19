import gzip
import hashlib
import ipaddress
import json
import os
import re
import tempfile
from pathlib import Path
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Cowrie Logs Analyzer",
    page_icon="🛡️",
    layout="wide",
)

st.title("Cowrie Logs Analyzer")

DEFAULT_DIR = Path(__file__).parent / "data"
LOG_FILE_PATTERN = re.compile(
    r"\.(?:jsonl?|log)(?:\.\d{4}-\d{2}-\d{2}|\.\d+)?(?:\.gz)?$",
    re.IGNORECASE,
)
COMMAND_EVENT_IDS = {"cowrie.command", "cowrie.command.input"}


@st.cache_data(show_spinner=False)
def parse_logs(files):
    records = []
    errors = []

    for filename, content in files:
        try:
            if filename.lower().endswith(".gz"):
                content = gzip.decompress(content)

            text = content.decode("utf-8", errors="replace")

        except Exception as exc:
            errors.append(f"{filename}: {exc}")
            continue

        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)

                if not isinstance(event, dict):
                    continue

                records.append({
                    "timestamp": (
                        event.get("timestamp")
                        or event.get("time")
                        or event.get("@timestamp")
                    ),
                    "eventid": event.get("eventid", "unknown"),
                    "src_ip": event.get("src_ip", "unknown"),
                    "src_port": event.get("src_port", ""),
                    "dst_ip": event.get("dst_ip", ""),
                    "dst_port": event.get("dst_port", ""),
                    "session": event.get("session", "unknown"),
                    "username": event.get("username", ""),
                    "password": event.get("password", ""),
                    "input": event.get("input", ""),
                    "message": event.get("message", ""),
                    "outfile": event.get("outfile", ""),
                    "shasum": event.get("shasum", ""),
                    "protocol": event.get("protocol", ""),
                    "version": event.get("version", ""),
                    "hassh": event.get("hassh", ""),
                    "duration_ms": event.get(
                        "duration_ms", event.get("duration", "")
                    ),
                    "source_file": filename,
                    "line_number": line_number,
                    "raw": json.dumps(event, ensure_ascii=False),
                })

            except (json.JSONDecodeError, ValueError):
                errors.append(
                    f"{filename}: invalid JSON at line {line_number}"
                )

    columns = [
        "timestamp", "eventid", "src_ip", "src_port", "dst_ip", "dst_port",
        "session", "username", "password", "input", "message", "outfile",
        "shasum", "protocol", "version", "hassh", "duration_ms",
        "source_file", "line_number", "raw",
    ]
    df = pd.DataFrame(records, columns=columns)

    if not df.empty:
        df["timestamp"] = pd.to_datetime(
            df["timestamp"], errors="coerce", utc=True
        )

        string_columns = [
            "eventid", "src_ip", "session", "username",
            "password", "input", "message", "outfile",
            "shasum", "protocol", "dst_ip",
            "version", "hassh",
        ]

        for column in string_columns:
            df[column] = df[column].fillna("").astype(str)

        for column in ["src_port", "dst_port", "duration_ms"]:
            df[column] = pd.to_numeric(df[column], errors="coerce")

        df["src_ip"] = df["src_ip"].replace("", "unknown")
        df["session"] = df["session"].replace("", "unknown")

    return df, errors


def resolve_data_root(folder):
    if folder is None or not folder.exists() or not folder.is_dir():
        return folder

    if folder.name in {"logs", "log"} and folder.parent.exists():
        return folder.parent

    if (folder / "logs").is_dir() or (folder / "log").is_dir():
        return folder

    return folder


def find_log_files(folder):
    if not folder or not folder.is_dir():
        return []

    search_roots = []
    base = resolve_data_root(folder)

    for candidate in [base, base / "logs", base / "log"]:
        if candidate.is_dir() and candidate not in search_roots:
            search_roots.append(candidate)

    matches = []
    for root in search_roots:
        for path in root.rglob("*"):
            if path.is_file() and not path.is_symlink() and LOG_FILE_PATTERN.search(path.name):
                matches.append(path)

    return sorted(set(matches))


def read_folder(folder):
    files = []
    for path in find_log_files(folder):
        try:
            files.append((str(path), path.read_bytes()))
        except OSError:
            pass
    return files


def validate_log_path(path, folder):
    root = folder.resolve(strict=True)
    target = path.resolve(strict=True)
    target.relative_to(root)

    if not target.is_file() or not LOG_FILE_PATTERN.search(target.name):
        raise ValueError("The selected file is not a recognized Cowrie log.")

    return target


def delete_log_entry(path, folder, line_number, expected_raw):
    target = validate_log_path(path, folder)
    content = target.read_bytes()
    compressed = target.name.lower().endswith(".gz")

    if compressed:
        content = gzip.decompress(content)

    lines = content.splitlines(keepends=True)
    if line_number < 1 or line_number > len(lines):
        raise ValueError("The selected log line no longer exists.")

    try:
        current_event = json.loads(
            lines[line_number - 1].decode("utf-8", errors="replace")
        )
        expected_event = json.loads(expected_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("The selected log line is no longer valid JSON.") from exc

    if current_event != expected_event:
        raise ValueError(
            "The log changed since it was loaded. Refresh and select the event again."
        )

    del lines[line_number - 1]
    updated_content = b"".join(lines)
    if compressed:
        updated_content = gzip.compress(updated_content)

    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(updated_content)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        os.replace(temporary_path, target)
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()

    return target


def safe_contains(series, query):
    return series.astype(str).str.contains(
        re.escape(query), case=False, na=False
    )


def command_preview(value, limit=160):
    compact = re.sub(r"\s+", " ", str(value)).strip()
    if len(compact) > limit:
        return compact[:limit - 3] + "..."
    return compact


def _is_valid_ip(value):
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


# --------------------------------------------------
# Sidebar: data sources
# --------------------------------------------------

with st.sidebar:
    st.header("Data source")

    folder_text = st.text_input(
        "Select a local folder",
        value=str(DEFAULT_DIR) if DEFAULT_DIR.exists() else "",
        key="log_folder",
        help="The folder is searched recursively, including subfolders.",
    )

folder = Path(folder_text).expanduser() if folder_text.strip() else None

if "deleted_event_notice" in st.session_state:
    st.sidebar.success(st.session_state.pop("deleted_event_notice"))

files = []

if folder:
    files.extend(read_folder(folder))

if not files:
    st.warning(
        "Enter the path to your log folder in the sidebar"
    )
    st.code(
        "streamlit run main.py",
        language="powershell",
    )
    st.stop()

with st.spinner("Reading and parsing Cowrie events..."):
    df, errors = parse_logs(tuple(files))

if df.empty:
    st.error(
        "No valid JSON events were found. Check that you selected "
        "Cowrie JSON logs containing one JSON object per line."
    )

    if errors:
        st.write(errors[:50])

    st.stop()

# --------------------------------------------------
# Filters
# --------------------------------------------------

st.sidebar.divider()
st.sidebar.header("Filters")

event_options = sorted(df["eventid"].unique())
ip_options = sorted(df["src_ip"].unique())

with st.sidebar:
    selected_events = st.multiselect(
        "Event types",
        event_options,
        default=[],
    )

    selected_ips = st.multiselect(
        "Source IP addresses",
        ip_options,
        default=[],
    )

    search_query = st.text_input(
        "Search everything",
        placeholder="wget, username, IP, session...",
    )

    valid_dates = df["timestamp"].dropna()

    if not valid_dates.empty:
        min_date = valid_dates.min().date()
        max_date = valid_dates.max().date()

        date_range = st.date_input(
            "Date range (UTC)",
            value=(min_date, max_date),
            min_value=min_date,
            max_value=max_date,
        )
    else:
        date_range = None

filtered = df.copy()

if selected_events:
    filtered = filtered[
        filtered["eventid"].isin(selected_events)
    ]

if selected_ips:
    filtered = filtered[
        filtered["src_ip"].isin(selected_ips)
    ]

if date_range and isinstance(date_range, (tuple, list)):
    if len(date_range) == 2:
        start_date, end_date = date_range

        start = pd.Timestamp(start_date, tz="UTC")
        end = pd.Timestamp(end_date, tz="UTC") + pd.Timedelta(days=1)

        filtered = filtered[
            filtered["timestamp"].isna()
            | (
                (filtered["timestamp"] >= start)
                & (filtered["timestamp"] < end)
            )
        ]

if search_query.strip():
    searchable = [
        "eventid", "src_ip", "session", "username",
        "password", "input", "message", "outfile", "shasum",
    ]

    mask = pd.Series(False, index=filtered.index)

    for column in searchable:
        mask |= safe_contains(filtered[column], search_query)

    filtered = filtered[mask]

if errors:
    with st.expander(f"Import warnings ({len(errors)})"):
        st.write(errors[:200])

# --------------------------------------------------
# Event subsets
# --------------------------------------------------

commands = filtered[
    filtered["eventid"].isin(COMMAND_EVENT_IDS)
    & (filtered["input"].str.strip() != "")
]

successful_logins = filtered[
    filtered["eventid"] == "cowrie.login.success"
]

auth = filtered[
    filtered["eventid"].isin([
        "cowrie.login.failed",
        "cowrie.login.success",
    ])
]

# --------------------------------------------------
# Summary
# --------------------------------------------------

st.subheader("Threat activity overview")

a, b, c, d, e = st.columns(5)

a.metric("Events", f"{len(filtered):,}")

known_ips = filtered.loc[
    filtered["src_ip"] != "unknown", "src_ip"
].nunique()

b.metric("Source IPs", f"{known_ips:,}")

known_sessions = filtered.loc[
    filtered["session"] != "unknown", "session"
].nunique()

c.metric("Sessions", f"{known_sessions:,}")
d.metric("Commands", f"{len(commands):,}")
e.metric("Successful logins", f"{len(successful_logins):,}")

st.caption(
    f"Analyzing {len(files)} log file(s) and "
    f"{len(df):,} valid events before filters."
)

overview, ips_tab, auth_tab, cmd_tab, session_tab, raw_tab = (
    st.tabs([
        "Overview",
        "Source IPs",
        "Authentication",
        "Commands",
        "Sessions",
        "Raw events",
    ])
)

# --------------------------------------------------
# Overview
# --------------------------------------------------

with overview:
    st.subheader("Event timeline")

    timed = filtered.dropna(subset=["timestamp"])

    if not timed.empty:
        timeline = (
            timed.set_index("timestamp")
            .resample("1h")
            .size()
            .rename("Events")
        )

        st.area_chart(timeline)

    else:
        st.info("No valid timestamps are available.")

    left, right = st.columns(2)

    with left:
        st.subheader("Event types")
        event_counts = filtered["eventid"].value_counts().head(10)
        if not event_counts.empty:
            st.bar_chart(event_counts, horizontal=True)
        else:
            st.info("No event types to display.")

    with right:
        st.subheader("Most active source IPs")
        ip_counts = filtered.loc[filtered["src_ip"] != "unknown", "src_ip"].value_counts().head(10)
        if not ip_counts.empty:
            st.bar_chart(ip_counts, horizontal=True)
        else:
            st.info("No known source IP addresses.")

    st.subheader("Most executed commands")

    if not commands.empty:
        st.dataframe(
            commands["input"]
            .value_counts()
            .head(20)
            .rename_axis("Command")
            .reset_index(name="Occurrences"),
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("No command events match your filters.")



# --------------------------------------------------
# Source IP analysis
# --------------------------------------------------

with ips_tab:
    st.subheader("Source IP investigation")

    if filtered.empty:
        st.info("No events match your filters.")

    else:
        # Build source IP summary
        ip_summary = (
            filtered.dropna(subset=["src_ip"])
            .groupby("src_ip")
            .agg(
                Events=("eventid", "size"),
                Sessions=("session", "nunique"),
                Commands=(
                    "eventid",
                    lambda x: int(
                        x.isin(COMMAND_EVENT_IDS).sum()
                    ),
                ),
                Failed_logins=(
                    "eventid",
                    lambda x: int(
                        (x == "cowrie.login.failed").sum()
                    ),
                ),
                Successful_logins=(
                    "eventid",
                    lambda x: int(
                        (x == "cowrie.login.success").sum()
                    ),
                ),
                First_seen=("timestamp", "min"),
                Last_seen=("timestamp", "max"),
            )
            .sort_values("Events", ascending=False)
            .reset_index()
        )

        # Create a display-only copy with clickable IPinfo URLs
        ip_summary_display = ip_summary.copy()

        ip_summary_display["src_ip"] = ip_summary_display[
            "src_ip"
        ].apply(
            lambda ip: (
                f"https://ipinfo.io/{ip}"
                if _is_valid_ip(ip)
                else ""
            )
        )

        st.dataframe(
            ip_summary_display,
            column_config={
                "src_ip": st.column_config.LinkColumn(
                    "Source IP",
                    display_text=r"https://ipinfo\.io/(.*)",
                    help="Click an IP address to open its IPinfo page.",
                ),
            },
            width="stretch",
            hide_index=True,
        )

        # Select an IP for detailed investigation
        available_ips = sorted(
            filtered["src_ip"].dropna().astype(str).unique()
        )

        if not available_ips:
            st.info("No source IP addresses are available.")

        else:
            selected_ip = st.selectbox(
                "Investigate one IP",
                available_ips,
                key="investigate_ip",
            )

            ip_events = filtered[
                filtered["src_ip"].astype(str) == selected_ip
            ].sort_values("timestamp")

            st.write(
                f"{len(ip_events):,} events associated with {selected_ip}"
            )

            # Display events for the selected IP
            event_columns = [
                "timestamp",
                "eventid",
                "session",
                "protocol",
                "src_port",
                "dst_ip",
                "dst_port",
                "version",
                "username",
                "input",
            ]

            available_columns = [
                col for col in event_columns
                if col in ip_events.columns
            ]

            st.dataframe(
                ip_events[available_columns],
                width="stretch",
                hide_index=True,
            )



# --------------------------------------------------
# Authentication
# --------------------------------------------------

with auth_tab:
    st.subheader("Authentication attempts")

    if auth.empty:
        st.info("No authentication events found.")
    else:
        auth_view = auth.copy()

        auth_view["Result"] = auth_view["eventid"].map({
            "cowrie.login.failed": "Failed",
            "cowrie.login.success": "Successful",
        })

        st.dataframe(
            auth_view[
                ["timestamp", "src_ip", "session", "username", "password", "Result"]
            ].sort_values("timestamp", ascending=False),
            width="stretch",
            hide_index=True,
        )

        left, right = st.columns(2)

        with left:
            st.write("Most attempted usernames")

            st.dataframe(
                auth["username"]
                .value_counts()
                .head(20)
                .rename_axis("Username")
                .reset_index(name="Attempts"),
                width="stretch",
                hide_index=True,
            )

        with right:
            st.write("Most attempted passwords")

            st.dataframe(
                auth["password"]
                .value_counts()
                .head(20)
                .rename_axis("Password")
                .reset_index(name="Attempts"),
                width="stretch",
                hide_index=True,
            )



# --------------------------------------------------
# Command investigation
# --------------------------------------------------

with cmd_tab:
    st.subheader("Executed commands")

    if commands.empty:
        st.info("No command input events match your filters.")

    else:
        command_view = commands.copy()

        # Ensure command input is treated as text
        command_view["input"] = (
            command_view["input"].fillna("").astype(str)
        )

        # --------------------------------------------------
        # Command categorization
        # --------------------------------------------------

        def classify_command_insight(command):
            cmd = str(command).lower().strip()

            rules = {
                "Reconnaissance": [
                    "uname", "whoami", "id", "hostname", "pwd",
                    "ifconfig", "ip addr", "ip route", "cat /etc/os-release",
                    "cat /etc/passwd", "env", "printenv", "ls",
                    "ps", "netstat", "ss -",
                ],
                "Download / Payload": [
                    "wget ", "curl ", "tftp ", "ftp ",
                    "busybox wget", "powershell -enc",
                ],
                "Permissions / Execution": [
                    "chmod ", "chown ", "bash ", "sh ",
                    "python -c", "perl -e", "nohup ",
                ],
                "Persistence": [
                    "crontab", "authorized_keys", "systemctl ",
                    "/etc/cron", "rc.local", "ssh-keygen",
                ],
                "Privilege Escalation": [
                    "sudo ", "su ", "pkexec", "doas ",
                ],
                "Defense Evasion": [
                    "history -c", "unset histfile",
                    "iptables ", "ufw ", "rm -rf",
                ],
                "Cryptocurrency Mining": [
                    "xmrig", "minerd", "stratum+tcp",
                    "cryptonight", "monero",
                ],
                "Credential / Secret Access": [
                    "/etc/shadow", ".ssh/id_rsa",
                    ".aws/credentials", "authorized_keys",
                ],
            }

            for category, indicators in rules.items():
                if any(indicator in cmd for indicator in indicators):
                    return category

            return "Other"

        command_view["Category"] = command_view["input"].map(
            classify_command_insight
        )

        # Simple indicators: candidates for manual review, not proof
        suspicious_patterns = [
            "wget ", "curl ", "chmod ", "xmrig", "minerd",
            "base64 -d", "/etc/shadow", "authorized_keys",
            "crontab", "rm -rf", "nc -e", "bash -i",
            "python -c", "perl -e",
        ]

        command_view["Review flag"] = command_view["input"].apply(
            lambda cmd: (
                "Review"
                if any(
                    pattern in cmd.lower()
                    for pattern in suspicious_patterns
                )
                else ""
            )
        )

        # --------------------------------------------------
        # Search and category filters
        # --------------------------------------------------

        command_query = st.text_input(
            "Filter command strings",
            placeholder="wget, curl, chmod, base64...",
            key="command_investigation_search",
        )

        selected_categories = st.multiselect(
            "Command categories",
            options=sorted(command_view["Category"].unique()),
            default=[],
            key="command_investigation_categories",
        )

        flagged_only = st.checkbox(
            "Show commands flagged for review only",
            key="command_investigation_flagged",
        )

        if command_query:
            command_view = command_view[
                safe_contains(command_view["input"], command_query)
            ]

        if selected_categories:
            command_view = command_view[
                command_view["Category"].isin(selected_categories)
            ]

        if flagged_only:
            command_view = command_view[
                command_view["Review flag"] == "Review"
            ]

        st.write(f"{len(command_view):,} command events match your filters")

        if command_view.empty:
            st.info("No commands match your search and filters.")

        else:
            # --------------------------------------------------
            # Summary metrics
            # --------------------------------------------------

            unique_commands = command_view["input"].nunique()

            flagged_events = int(
                (command_view["Review flag"] == "Review").sum()
            )

            unique_sources = (
                command_view["src_ip"].nunique()
                if "src_ip" in command_view.columns
                else 0
            )

            unique_sessions = (
                command_view["session"].nunique()
                if "session" in command_view.columns
                else 0
            )

            m1, m2, m3, m4 = st.columns(4)

            m1.metric("Command events", f"{len(command_view):,}")
            m2.metric("Unique commands", f"{unique_commands:,}")
            m3.metric("Flagged for review", f"{flagged_events:,}")
            m4.metric("Source IPs", f"{unique_sources:,}")

            st.caption(f"Distinct sessions: {unique_sessions:,}")

            # --------------------------------------------------
            # Category distribution
            # --------------------------------------------------

            st.subheader("Command category distribution")

            category_counts = (
                command_view["Category"]
                .value_counts()
                .rename_axis("Category")
                .reset_index(name="Occurrences")
            )

            st.bar_chart(
                category_counts.set_index("Category")["Occurrences"]
            )

            # --------------------------------------------------
            # Most frequent commands
            # --------------------------------------------------

            st.subheader("Most frequent commands")

            command_summary = (
                command_view.groupby("input", as_index=False)
                .agg(
                    Occurrences=("input", "size"),
                    Categories=("Category", "first"),
                    Review=("Review flag", "first"),
                )
            )

            command_summary["Command preview"] = command_summary[
                "input"
            ].map(command_preview)

            command_summary = command_summary.sort_values(
                "Occurrences",
                ascending=False,
            )

            st.dataframe(
                command_summary[
                    [
                        "Command preview",
                        "Occurrences",
                        "Categories",
                        "Review",
                    ]
                ],
                column_config={
                    "Command preview": st.column_config.TextColumn(
                        width="large"
                    ),
                    "Occurrences": st.column_config.NumberColumn(
                        width="small"
                    ),
                    "Categories": st.column_config.TextColumn(
                        width="medium"
                    ),
                    "Review": st.column_config.TextColumn(
                        width="small"
                    ),
                },
                width="stretch",
                hide_index=True,
            )

            # --------------------------------------------------
            # Source IPs associated with commands
            # --------------------------------------------------

            if "src_ip" in command_view.columns:
                st.subheader("Sources issuing the most commands")

                source_counts = (
                    command_view.groupby("src_ip", as_index=False)
                    .agg(
                        Command_events=("input", "size"),
                        Unique_commands=("input", "nunique"),
                    )
                    .sort_values(
                        "Command_events",
                        ascending=False,
                    )
                    .head(15)
                )

                st.dataframe(
                    source_counts,
                    width="stretch",
                    hide_index=True,
                )

            # --------------------------------------------------
            # Session investigation
            # --------------------------------------------------

            if "session" in command_view.columns:
                sessions = sorted(
                    command_view["session"]
                    .dropna()
                    .astype(str)
                    .unique()
                )

                if sessions:
                    st.subheader("Investigate command session")

                    selected_session = st.selectbox(
                        "Select a session",
                        sessions,
                        key="command_investigation_session",
                    )

                    session_events = command_view[
                        command_view["session"].astype(str)
                        == selected_session
                    ].sort_values("timestamp")

                    st.write(
                        f"{len(session_events):,} matching commands "
                        f"in session {selected_session}"
                    )

                    session_columns = [
                        col for col in [
                            "timestamp", "src_ip", "session",
                            "input", "Category", "Review flag",
                        ]
                        if col in session_events.columns
                    ]

                    st.dataframe(
                        session_events[session_columns],
                        width="stretch",
                        hide_index=True,
                    )

            # --------------------------------------------------
            # Complete command event details
            # --------------------------------------------------

            st.subheader("Command event details")

            detail_columns = [
                col for col in [
                    "timestamp", "src_ip", "session", "src_port",
                    "input", "Category", "Review flag",
                ]
                if col in command_view.columns
            ]

            command_details = command_view[detail_columns].copy()

            if "timestamp" in command_details.columns:
                command_details = command_details.sort_values(
                    "timestamp",
                    ascending=False,
                )

            command_details = command_details.rename(
                columns={
                    "timestamp": "Time (UTC)",
                    "src_ip": "Source IP",
                    "session": "Session",
                    "src_port": "Source port",
                    "input": "Command",
                }
            )

            st.dataframe(
                command_details,
                column_config={
                    "Command": st.column_config.TextColumn(
                        width="large"
                    ),
                    "Time (UTC)": st.column_config.DatetimeColumn(
                        format="YYYY-MM-DD HH:mm:ss"
                    ),
                },
                width="stretch",
                hide_index=True,
            )

            # --------------------------------------------------
            # Export filtered command findings
            # --------------------------------------------------

            st.subheader("Export command findings")

            export_data = command_details.to_csv(
                index=False
            ).encode("utf-8")

            st.download_button(
                "Download command findings as CSV",
                data=export_data,
                file_name="cowrie_command_findings.csv",
                mime="text/csv",
                key="download_command_findings",
            )



# --------------------------------------------------
# Session reconstruction and investigation
# --------------------------------------------------

with session_tab:
    st.subheader("Reconstruct an attacker session")

    if filtered.empty:
        st.info("No events match your filters.")

    elif "session" not in filtered.columns:
        st.error("The filtered dataset has no session column.")

    else:
        # Exclude missing and unknown session identifiers
        session_ids = sorted(
            filtered.loc[
                filtered["session"].notna()
                & (filtered["session"].astype(str) != "unknown"),
                "session",
            ].astype(str).unique()
        )

        if not session_ids:
            st.info("No session identifiers found.")

        else:
            chosen_session = st.selectbox(
                "Select a session ID",
                session_ids,
                key="reconstruct_session",
            )

            session_data = filtered[
                filtered["session"].astype(str) == chosen_session
            ].copy()

            if "timestamp" in session_data.columns:
                session_data = session_data.sort_values(
                    "timestamp"
                )

            if session_data.empty:
                st.info("No events found for this session.")

            else:
                # --------------------------------------------------
                # Session overview
                # --------------------------------------------------

                st.subheader("Session overview")

                total_events = len(session_data)

                source_ip = (
                    session_data["src_ip"].dropna().iloc[0]
                    if "src_ip" in session_data.columns
                    and session_data["src_ip"].notna().any()
                    else "Unknown"
                )

                username_values = (
                    session_data["username"]
                    .dropna()
                    .astype(str)
                    .unique()
                    if "username" in session_data.columns
                    else []
                )

                usernames = ", ".join(username_values[:5]) or "Unknown"

                command_count = (
                    int(
                        session_data["eventid"]
                        .isin(COMMAND_EVENT_IDS)
                        .sum()
                    )
                    if "eventid" in session_data.columns
                    else 0
                )

                failed_logins = (
                    int(
                        (
                            session_data["eventid"]
                            == "cowrie.login.failed"
                        ).sum()
                    )
                    if "eventid" in session_data.columns
                    else 0
                )

                successful_logins = (
                    int(
                        (
                            session_data["eventid"]
                            == "cowrie.login.success"
                        ).sum()
                    )
                    if "eventid" in session_data.columns
                    else 0
                )

                c1, c2, c3, c4 = st.columns(4)

                c1.metric("Total events", f"{total_events:,}")
                c2.metric("Command events", f"{command_count:,}")
                c3.metric("Failed logins", failed_logins)
                c4.metric("Successful logins", successful_logins)

                st.write(f"**Session ID:** `{chosen_session}`")
                st.write(f"**Source IP:** {source_ip}")
                st.write(f"**Observed usernames:** {usernames}")

                if "timestamp" in session_data.columns:
                    timestamps = session_data["timestamp"].dropna()

                    if not timestamps.empty:
                        first_seen = timestamps.min()
                        last_seen = timestamps.max()

                        st.write(f"**First event:** {first_seen}")
                        st.write(f"**Last event:** {last_seen}")

                        duration_seconds = (
                            last_seen - first_seen
                        ).total_seconds()

                        st.metric(
                            "Observed session span",
                            f"{duration_seconds:.1f} seconds",
                        )

                # --------------------------------------------------
                # Event timeline
                # --------------------------------------------------

                st.subheader("Session event timeline")

                if (
                    "timestamp" in session_data.columns
                    and "eventid" in session_data.columns
                ):
                    timeline = session_data[
                        ["timestamp", "eventid"]
                    ].dropna(subset=["timestamp"]).copy()

                    if not timeline.empty:
                        timeline["Event count"] = 1

                        st.dataframe(
                            timeline,
                            width="stretch",
                            hide_index=True,
                        )

                        event_counts = (
                            session_data["eventid"]
                            .fillna("Unknown")
                            .value_counts()
                            .rename_axis("Event type")
                            .reset_index(name="Count")
                        )

                        st.subheader("Event type distribution")

                        st.bar_chart(
                            event_counts.set_index("Event type")["Count"]
                        )

                # --------------------------------------------------
                # Command history
                # --------------------------------------------------

                st.subheader("Command history")

                if "input" in session_data.columns:
                    command_events = session_data[
                        session_data["input"].notna()
                        & (
                            session_data["input"]
                            .astype(str)
                            .str.strip()
                            .ne("")
                        )
                    ].copy()

                    if not command_events.empty:
                        command_columns = [
                            col for col in [
                                "timestamp",
                                "src_ip",
                                "eventid",
                                "input",
                            ]
                            if col in command_events.columns
                        ]

                        st.dataframe(
                            command_events[command_columns],
                            width="stretch",
                            hide_index=True,
                        )
                    else:
                        st.info(
                            "No command input was recorded in this session."
                        )

                # --------------------------------------------------
                # Session evidence
                # --------------------------------------------------

                st.subheader("Complete session evidence")

                evidence_columns = [
                    "timestamp",
                    "eventid",
                    "src_ip",
                    "src_port",
                    "dst_ip",
                    "dst_port",
                    "protocol",
                    "version",
                    "hassh",
                    "duration_ms",
                    "username",
                    "input",
                    "message",
                    "shasum",
                ]

                available_columns = [
                    col for col in evidence_columns
                    if col in session_data.columns
                ]

                evidence = session_data[available_columns]

                st.dataframe(
                    evidence,
                    width="stretch",
                    hide_index=True,
                )

                # --------------------------------------------------
                # Download session evidence
                # --------------------------------------------------

                csv_data = evidence.to_csv(
                    index=False
                ).encode("utf-8")

                st.download_button(
                    "Download session evidence (CSV)",
                    data=csv_data,
                    file_name=f"cowrie_session_{chosen_session}.csv",
                    mime="text/csv",
                    key="download_session_evidence",
                )



# --------------------------------------------------
# Raw events
# --------------------------------------------------

with raw_tab:
    st.subheader("Raw event browser")

    if filtered.empty:
        st.info("No events match the current filters.")

    else:
        raw_view = filtered.copy()

        # --------------------------------------------------
        # Search and filters
        # --------------------------------------------------

        st.subheader("Search and filter events")

        search_query = st.text_input(
            "Search event contents",
            placeholder="IP address, username, command, message...",
            key="raw_event_search",
        )

        filter_col1, filter_col2 = st.columns(2)

        with filter_col1:
            available_event_ids = sorted(
                raw_view["eventid"]
                .dropna()
                .astype(str)
                .unique()
            )

            selected_event_ids = st.multiselect(
                "Event types",
                options=available_event_ids,
                key="raw_event_types",
            )

        with filter_col2:
            available_ips = sorted(
                raw_view["src_ip"]
                .dropna()
                .astype(str)
                .unique()
            )

            selected_ips = st.multiselect(
                "Source IP addresses",
                options=available_ips,
                key="raw_event_ips",
            )

        if selected_event_ids:
            raw_view = raw_view[
                raw_view["eventid"].astype(str).isin(
                    selected_event_ids
                )
            ]

        if selected_ips:
            raw_view = raw_view[
                raw_view["src_ip"].astype(str).isin(selected_ips)
            ]

        if search_query.strip():
            searchable_columns = [
                col for col in [
                    "eventid",
                    "src_ip",
                    "dst_ip",
                    "session",
                    "username",
                    "input",
                    "message",
                    "source_file",
                ]
                if col in raw_view.columns
            ]

            search_mask = (
                raw_view[searchable_columns]
                .fillna("")
                .astype(str)
                .apply(
                    lambda column: safe_contains(
                        column, search_query
                    )
                )
                .any(axis=1)
            )

            raw_view = raw_view[search_mask]

        # --------------------------------------------------
        # Summary
        # --------------------------------------------------

        st.subheader("Event overview")

        metric1, metric2, metric3 = st.columns(3)

        metric1.metric(
            "Matching events",
            f"{len(raw_view):,}",
        )

        metric2.metric(
            "Unique source IPs",
            (
                raw_view["src_ip"].nunique()
                if "src_ip" in raw_view.columns
                else 0
            ),
        )

        metric3.metric(
            "Unique sessions",
            (
                raw_view["session"].nunique()
                if "session" in raw_view.columns
                else 0
            ),
        )

        if raw_view.empty:
            st.info("No events match your search and filters.")

        else:
            # --------------------------------------------------
            # Raw event table
            # --------------------------------------------------

            st.subheader("Matching raw events")

            display_columns = [
                "timestamp",
                "eventid",
                "src_ip",
                "session",
                "src_port",
                "dst_ip",
                "dst_port",
                "protocol",
                "version",
                "hassh",
                "duration_ms",
                "username",
                "input",
                "message",
                "source_file",
                "line_number",
            ]

            available_columns = [
                col for col in display_columns
                if col in raw_view.columns
            ]

            raw_sorted = raw_view.sort_values(
                "timestamp",
                ascending=False,
            )

            st.dataframe(
                raw_sorted[available_columns],
                width="stretch",
                hide_index=True,
            )

            # --------------------------------------------------
            # Export filtered events
            # --------------------------------------------------

            export_columns = [
                col for col in raw_view.columns
                if col != "raw"
            ]

            export_csv = raw_view[export_columns].to_csv(
                index=False
            ).encode("utf-8")

            st.download_button(
                "Download filtered events as CSV",
                data=export_csv,
                file_name="cowrie_filtered_events.csv",
                mime="text/csv",
                key="download_raw_events",
            )

            # --------------------------------------------------
            # Individual JSON event inspection
            # --------------------------------------------------

            st.subheader("Inspect an individual JSON event")

            # Use the original DataFrame index to identify the source row.
            event_labels = {}

            for index, row in raw_view.iterrows():
                timestamp = row.get("timestamp", "Unknown time")
                event_id = row.get("eventid", "Unknown event")
                src_ip = row.get("src_ip", "Unknown IP")
                source_file = Path(
                    str(row.get("source_file", "unknown"))
                ).name
                line_number = row.get("line_number", "?")

                event_labels[index] = (
                    f"{timestamp} | {event_id} | {src_ip} | "
                    f"{source_file}:{line_number}"
                )

            event_index = st.selectbox(
                "Select event",
                options=raw_view.index.tolist(),
                format_func=event_labels.__getitem__,
                key="raw_event_inspector",
            )

            selected_event = raw_view.loc[event_index]

            try:
                raw_json = json.loads(selected_event["raw"])
            except (ValueError, TypeError, KeyError):
                st.warning(
                    "The raw event is missing or is not valid JSON."
                )
                raw_json = None

            if raw_json is not None:
                st.json(raw_json)

                # --------------------------------------------------
                # Permanent deletion
                # --------------------------------------------------

                st.subheader("Delete this event")

                st.warning(
                    "This permanently removes the selected JSON line "
                    "from its source log. Back up the original log first."
                )

                st.write("**Selected event:**")
                st.code(event_labels[event_index])

                confirm_event_delete = st.checkbox(
                    "I understand this permanently deletes the selected event.",
                    key=(
                        f"confirm_event_delete_"
                        f"{selected_event.get('source_file', 'unknown')}_"
                        f"{selected_event.get('line_number', 'unknown')}"
                    ),
                )

                delete_event_submitted = st.button(
                    "Delete selected event permanently",
                    disabled=not confirm_event_delete,
                    type="primary",
                    key="delete_selected_raw_event",
                )

                if delete_event_submitted:
                    try:
                        deleted_source = delete_log_entry(
                            Path(selected_event["source_file"]),
                            folder,
                            int(selected_event["line_number"]),
                            selected_event["raw"],
                        )

                    except (
                        OSError,
                        ValueError,
                        gzip.BadGzipFile,
                        KeyError,
                        TypeError,
                    ) as exc:
                        st.error(
                            f"Could not delete the selected event: {exc}"
                        )

                    else:
                        st.cache_data.clear()

                        st.session_state["deleted_event_notice"] = (
                            f"Removed one event from "
                            f"{deleted_source.name}."
                        )

                        st.rerun()


st.divider()
