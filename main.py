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
    page_title="Cowrie Log Analyzer",
    page_icon="🛡️",
    layout="wide",
)

st.title("Cowrie Log Analyzer")

DEFAULT_DIR = Path(__file__).parent / "data"
LOG_FILE_PATTERN = re.compile(
    r"\.(?:jsonl?|log)(?:\.\d{4}-\d{2}-\d{2}|\.\d+)?(?:\.gz)?$",
    re.IGNORECASE,
)
COMMAND_EVENT_IDS = {"cowrie.command", "cowrie.command.input"}
COMMAND_OUTCOME_LABELS = {
    "cowrie.command.success": "Recognized",
    "cowrie.command.failed": "Not recognized",
}


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
                    "sensor": event.get("sensor", ""),
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
        "shasum", "sensor", "protocol", "version", "hassh", "duration_ms",
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
            "shasum", "sensor", "protocol", "dst_ip",
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


def build_lib_manifest(folder):
    if folder is None or not folder.exists():
        return []

    root = resolve_data_root(folder)
    lib_dir = root / "lib"
    if not lib_dir.is_dir():
        return []

    manifest = []
    for path in sorted(lib_dir.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue

        try:
            relative_path = path.relative_to(folder)
            size = path.stat().st_size
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            continue

        manifest.append({
            "path": str(path),
            "relative_path": str(relative_path),
            "name": path.name,
            "parent": str(path.parent.relative_to(folder)),
            "kind": (
                "downloads"
                if "downloads" in relative_path.parts
                else "config"
            ),
            "size_bytes": size,
            "sha256": digest,
        })

    return manifest


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


def preview_file_contents(path, limit=4000):
    try:
        data = path.read_bytes()
    except OSError:
        return None

    if not data:
        return ""

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        sample = data[:limit]
        return sample.hex()

    text = text.replace("\r\n", "\n")
    if len(text) > limit:
        return text[:limit] + "\n... (truncated)"
    return text


# --------------------------------------------------
# Sidebar: data sources
# --------------------------------------------------

with st.sidebar:
    st.header("Data source")

    folder_text = st.text_input(
        "Or select a local folder",
        value=str(DEFAULT_DIR) if DEFAULT_DIR.exists() else "",
        key="log_folder",
        help="The folder is searched recursively, including subfolders.",
    )

folder = Path(folder_text).expanduser() if folder_text.strip() else None
log_paths = find_log_files(folder) if folder else []

if "deleted_event_notice" in st.session_state:
    st.sidebar.success(st.session_state.pop("deleted_event_notice"))

files = []

if folder:
    files.extend(read_folder(folder))

lib_manifest = build_lib_manifest(folder)

if not files and not lib_manifest:
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

if df.empty and not lib_manifest:
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

command_outcomes = filtered[
    filtered["eventid"].isin(COMMAND_OUTCOME_LABELS)
    & (filtered["input"].str.strip() != "")
].copy()
command_outcomes["Result"] = command_outcomes["eventid"].map(
    COMMAND_OUTCOME_LABELS
)

failed_logins = filtered[
    filtered["eventid"] == "cowrie.login.failed"
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

file_events = filtered[
    filtered["eventid"].str.contains(
        r"file_download|file_upload",
        case=False,
        na=False,
    )
    | (filtered["outfile"].str.strip() != "")
    | (filtered["shasum"].str.strip() != "")
]

# --------------------------------------------------
# Summary
# --------------------------------------------------

st.subheader("Threat activity overview")

a, b, c, d, e, f = st.columns(6)

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
f.metric("Artifacts", f"{len(lib_manifest):,}")

st.caption(
    f"Analyzing {len(files)} log file(s), "
    f"{len(lib_manifest)} lib artifact(s), and "
    f"{len(df):,} valid events before filters."
)

overview, ips_tab, auth_tab, cmd_tab, session_tab, files_tab, raw_tab = (
    st.tabs([
        "Overview",
        "Source IPs",
        "Authentication",
        "Commands",
        "Sessions",
        "File activity",
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

        st.line_chart(timeline)

    else:
        st.info("No valid timestamps are available.")

    left, right = st.columns(2)

    with left:
        st.subheader("Most common event types")

        event_counts = filtered["eventid"].value_counts().head(15)

        if not event_counts.empty:
            st.bar_chart(event_counts)

    with right:
        st.subheader("Most active source IPs")

        ip_counts = (
            filtered[filtered["src_ip"] != "unknown"]["src_ip"]
            .value_counts()
            .head(15)
        )

        if not ip_counts.empty:
            st.bar_chart(ip_counts)

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
        ip_summary = (
            filtered.groupby("src_ip")
            .agg(
                Events=("eventid", "size"),
                Sessions=("session", "nunique"),
                Commands=(
                    "eventid",
                    lambda x: int(x.isin(COMMAND_EVENT_IDS).sum()),
                ),
                Failed_logins=(
                    "eventid",
                    lambda x: int((x == "cowrie.login.failed").sum()),
                ),
                Successful_logins=(
                    "eventid",
                    lambda x: int((x == "cowrie.login.success").sum()),
                ),
                First_seen=("timestamp", "min"),
                Last_seen=("timestamp", "max"),
            )
            .sort_values("Events", ascending=False)
            .reset_index()
        )

        st.dataframe(
            ip_summary,
            width="stretch",
            hide_index=True,
        )

        selected_ip = st.selectbox(
            "Investigate one IP",
            sorted(filtered["src_ip"].unique()),
            key="investigate_ip",
        )

        ip_events = filtered[
            filtered["src_ip"] == selected_ip
        ].sort_values("timestamp")

        st.write(f"{len(ip_events):,} events associated with {selected_ip}")

        try:
            ip_address = ipaddress.ip_address(selected_ip)
        except ValueError:
            st.info("This source value is not a valid IP address to look up.")
        else:
            st.link_button(
                "Look up IP on ipinfo.io",
                f"https://ipinfo.io/{ip_address}",
            )

        st.dataframe(
            ip_events[
                [
                    "timestamp", "eventid", "session", "protocol",
                    "src_port", "dst_ip", "dst_port", "version",
                    "username", "input",
                ]
            ],
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
        st.info(
            "No command input events match your filters."
        )
    else:
        command_query = st.text_input(
            "Filter command strings",
            placeholder="wget, curl, chmod, base64...",
        )

        command_view = commands.copy()

        if command_query:
            command_view = command_view[
                safe_contains(command_view["input"], command_query)
            ]

        st.write(f"{len(command_view):,} command events")

        if command_view.empty:
            st.info("No commands match your search.")
        else:
            command_view["Occurrences"] = command_view.groupby("input")[
                "input"
            ].transform("size")
            command_view["Command preview"] = command_view["input"].map(
                command_preview
            )

            st.dataframe(
                command_view[
                    [
                        "timestamp", "src_ip", "session", "Occurrences",
                        "Command preview",
                    ]
                ].sort_values("timestamp", ascending=False),
                width="stretch",
                hide_index=True,
            )

            command_index = st.selectbox(
                "Inspect full command input",
                command_view.index.tolist(),
                format_func=lambda index: (
                    f"{command_view.loc[index, 'timestamp']} | "
                    f"{command_preview(command_view.loc[index, 'input'], 80)}"
                ),
            )
            st.code(command_view.loc[command_index, "input"], language="bash")

    st.subheader("Command resolution outcomes")
    st.caption(
        "Recognized means Cowrie found a command handler; it does not "
        "confirm the command completed successfully."
    )

    if command_outcomes.empty:
        st.info("No command resolution outcomes match your filters.")
    else:
        command_outcomes["Command preview"] = command_outcomes[
            "input"
        ].map(command_preview)
        st.dataframe(
            command_outcomes[
                [
                    "timestamp", "src_ip", "session", "Result",
                    "Command preview", "message",
                ]
            ].sort_values("timestamp", ascending=False),
            width="stretch",
            hide_index=True,
        )

# --------------------------------------------------
# Session reconstruction
# --------------------------------------------------

with session_tab:
    st.subheader("Reconstruct an attacker session")

    session_ids = sorted(
        s for s in filtered["session"].unique()
        if s != "unknown"
    )

    if not session_ids:
        st.info("No session identifiers found.")
    else:
        chosen_session = st.selectbox(
            "Select a session ID",
            session_ids,
        )

        session_data = filtered[
            filtered["session"] == chosen_session
        ].sort_values("timestamp")

        if not session_data.empty:
            st.write(f"Events in session: {len(session_data)}")

            st.dataframe(
                session_data[
                    [
                        "timestamp", "eventid", "src_ip",
                        "src_port", "dst_ip", "dst_port", "protocol",
                        "version", "hassh", "duration_ms", "username",
                        "input", "message", "outfile", "shasum",
                    ]
                ],
                width="stretch",
                hide_index=True,
            )


# --------------------------------------------------
# File activity
# --------------------------------------------------

with files_tab:
    st.subheader("Recorded file activity and hashes")

    if file_events.empty:
        st.info(
            "No matching file events were found. Some file activity "
            "may be represented by different event types in your logs."
        )
    else:
        st.dataframe(
            file_events[
                [
                    "timestamp", "eventid", "src_ip",
                    "session", "outfile", "shasum", "message",
                ]
            ].sort_values("timestamp", ascending=False),
            width="stretch",
            hide_index=True,
        )

        hashes = file_events[
            file_events["shasum"].str.strip() != ""
        ]["shasum"].value_counts()

    st.subheader("lib artifacts")

    if not lib_manifest:
        st.info(
            "No Cowrie lib directory was found under the selected data folder. "
            "Cowrie typically stores files like SSH keys, UUIDs, tty state, and "
            "downloaded samples under a local lib/ directory."
        )
    else:
        lib_df = pd.DataFrame(lib_manifest)
        lib_table = lib_df[
            ["relative_path", "kind", "size_bytes", "sha256"]
        ].rename(columns={
            "relative_path": "Path",
            "kind": "Type",
            "size_bytes": "Size (bytes)",
            "sha256": "SHA256",
        })

        st.dataframe(
            lib_table,
            width="stretch",
            hide_index=True,
        )

        lib_downloads = lib_df[lib_df["kind"] == "downloads"]
        if not lib_downloads.empty:
            st.subheader("Downloaded artifacts")
            st.dataframe(
                lib_downloads[
                    ["relative_path", "size_bytes", "sha256"]
                ].rename(columns={
                    "relative_path": "Path",
                    "size_bytes": "Size (bytes)",
                    "sha256": "SHA256",
                }),
                width="stretch",
                hide_index=True,
            )

        selected_artifact = st.selectbox(
            "Inspect lib file contents",
            lib_df["relative_path"].tolist(),
            key="inspect_lib_artifact",
        )

        selected_path = Path(
            lib_df.loc[lib_df["relative_path"] == selected_artifact, "path"].iloc[0]
        )
        st.write(f"Selected file: {selected_artifact}")
        preview = preview_file_contents(selected_path)

        if preview is None:
            st.warning("The selected file could not be read.")
        else:
            st.code(preview, language="text")

# --------------------------------------------------
# Raw events
# --------------------------------------------------

with raw_tab:
    st.subheader("Raw event browser")

    if filtered.empty:
        st.info("No events match the current filters.")
    else:
        event_labels = {
            index: (
                f"{filtered.loc[index, 'timestamp']} | "
                f"{filtered.loc[index, 'eventid']} | "
                f"{filtered.loc[index, 'src_ip']} | "
                f"{Path(filtered.loc[index, 'source_file']).name}:"
                f"{filtered.loc[index, 'line_number']}"
            )
            for index in filtered.index
        }

        st.dataframe(
            filtered[
                [
                    "timestamp", "eventid", "src_ip", "session",
                    "src_port", "dst_ip", "dst_port", "protocol",
                    "version", "hassh", "duration_ms", "username",
                    "input", "message", "source_file", "line_number",
                ]
            ].sort_values("timestamp", ascending=False),
            width="stretch",
            hide_index=True,
        )

        event_index = st.selectbox(
            "Inspect an individual JSON event",
            filtered.index.tolist(),
            format_func=event_labels.__getitem__,
        )

        selected_event = filtered.loc[event_index]
        st.json(json.loads(selected_event["raw"]))

        st.subheader("Delete this event")
        st.caption(
            "This permanently removes only the selected JSON line from its "
            "source log. The action cannot be undone."
        )
        confirm_event_delete = st.checkbox(
            "I understand this permanently deletes the selected event.",
            key=(
                f"confirm_event_delete_{selected_event['source_file']}_"
                f"{selected_event['line_number']}"
            ),
        )
        delete_event_submitted = st.button(
            "Delete selected event permanently",
            disabled=not confirm_event_delete,
            type="primary",
        )

        if delete_event_submitted:
            try:
                deleted_source = delete_log_entry(
                    Path(selected_event["source_file"]),
                    folder,
                    int(selected_event["line_number"]),
                    selected_event["raw"],
                )
            except (OSError, ValueError, gzip.BadGzipFile) as exc:
                st.error(f"Could not delete the selected event: {exc}")
            else:
                st.cache_data.clear()
                st.session_state["deleted_event_notice"] = (
                    f"Removed one event from {deleted_source.name}."
                )
                st.rerun()


st.divider()