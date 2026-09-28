"""
FORENSIC-X — CSV & Plaso Super-Timeline Parser
app/analysis/parsers/csv_timeline_parser.py
"""

import csv
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from app.analysis.parsers.base import BaseParser, ParsedEvent


class CsvTimelineParser(BaseParser):
    """Parser for forensic timeline CSV files (Plaso, log2timeline, Eric Zimmerman tools)."""

    parser_name = "Forensic CSV Timeline Parser"
    supported_types = ["csv_timeline", "plaso_csv", "timeline_csv"]

    def can_parse(self, file_path: Path, sample_content: str) -> bool:
        if file_path.suffix.lower() == ".csv":
            return True
        lines = sample_content.splitlines()[:2]
        if lines and ("," in lines[0] or "\t" in lines[0]):
            return any(k in lines[0].lower() for k in ["datetime", "timestamp", "date", "time", "message", "desc"])
        return False

    def parse(self, file_path: Path, max_events: int = 5000) -> List[ParsedEvent]:
        events = []

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            # Check delimiter
            sample = f.read(2048)
            f.seek(0)
            delimiter = "\t" if "\t" in sample and sample.count("\t") > sample.count(",") else ","

            reader = csv.DictReader(f, delimiter=delimiter)
            if not reader.fieldnames:
                return events

            # Normalize column names
            col_map = {c.strip().lower(): c for c in reader.fieldnames if c}

            # Identify timestamp column
            ts_col = next(
                (col_map[k] for k in ["datetime", "timestamp", "date_time", "event_time", "time", "date"] if k in col_map),
                None,
            )
            desc_col = next(
                (col_map[k] for k in ["description", "message", "desc", "event", "summary", "display_name"] if k in col_map),
                None,
            )
            src_col = next(
                (col_map[k] for k in ["source", "source_type", "parser", "type", "data_type"] if k in col_map),
                None,
            )
            user_col = next(
                (col_map[k] for k in ["username", "user", "account", "user_name"] if k in col_map),
                None,
            )
            ip_col = next(
                (col_map[k] for k in ["source_ip", "ip", "src_ip", "client_ip", "ip_address"] if k in col_map),
                None,
            )

            for row in reader:
                if len(events) >= max_events:
                    break

                raw_ts = row.get(ts_col) if ts_col else None
                desc = row.get(desc_col) if desc_col else str(row)
                src = row.get(src_col) if src_col else file_path.name
                user = row.get(user_col) if user_col else None
                ip = row.get(ip_col) if ip_col else None

                parsed_ts = datetime.now(timezone.utc)
                if raw_ts:
                    try:
                        # Try ISO or common formats
                        if "T" in raw_ts:
                            parsed_ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                        else:
                            for fmt in ["%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"]:
                                try:
                                    parsed_ts = datetime.strptime(raw_ts[:19], fmt).replace(tzinfo=timezone.utc)
                                    break
                                except ValueError:
                                    pass
                    except Exception:
                        pass

                events.append(
                    ParsedEvent(
                        event_timestamp=parsed_ts,
                        source=str(src)[:100],
                        event_type="timeline_event",
                        description=str(desc)[:300],
                        severity="info",
                        source_ip=str(ip) if ip else None,
                        username=str(user) if user else None,
                        tags="csv,timeline",
                    )
                )

        return events
