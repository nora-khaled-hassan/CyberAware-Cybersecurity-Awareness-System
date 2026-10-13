from __future__ import annotations

import json
import random
import re
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd

from member1_incident_core import (
    ACTION_FIELDS,
    AFFECTED_SCOPES,
    CATEGORIES,
    INCIDENT_FIELDS,
    Incident,
    SEVERITY_LEVELS,
    STATUSES,
    URGENCY_LEVELS,
)

APP_DATETIME_FORMAT = "%d/%m/%Y %I:%M %p"
INCIDENT_ID_PATTERN = re.compile(r"^INC-\d+$")
RESULT_ID_PATTERN = re.compile(r"^RES-\d+$")

UNRESOLVED_STATUSES = ("Submitted", "Under Review")
QUIZ_STAGES = ("pre-training", "post-training")

ARTICLE_FIELDS = (
    "article_id",
    "title",
    "category",
    "summary",
    "content",
    "source_name",
    "source_url",
    "published_at",
)

QUIZ_QUESTION_FIELDS = (
    "question_id",
    "topic",
    "question",
    "options",
    "correct_option",
    "explanation",
)

QUIZ_RESULT_FIELDS = (
    "result_id",
    "participant_code",
    "quiz_stage",
    "quiz_date",
    "score",
    "total_questions",
)

REQUIRED_INCIDENT_FIELDS = (
    "incident_id",
    "reported_at",
    "category",
    "description",
    "severity",
    "urgency",
    "affected_scope",
    "status",
)

DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "data"
SYNTHETIC_SEED = 42


class CyberAwareError(Exception):
    """Base error for storage and analytics"""


class StorageError(CyberAwareError):
    """Raised when a data file cannot be read or written safely"""


def _is_blank(value):
    if value is None:
        return True
    if isinstance(value, float) and pd.isna(value):
        return True
    if isinstance(value, str) and not value.strip():
        return True
    text = str(value).strip()
    return text.lower() in {"nan", "nat", "none", "null"}


def _as_text(value):
    if _is_blank(value):
        return ""
    return str(value).strip()


def format_app_datetime(value):
    """Format a datetime using English AM/PM"""
    hour = value.hour % 12
    if hour == 0:
        hour = 12
    suffix = "AM" if value.hour < 12 else "PM"
    return (
        f"{value.day:02d}/{value.month:02d}/{value.year} "
        f"{hour:02d}:{value.minute:02d} {suffix}"
    )


def parse_app_datetime(value):
    """Parse DD/MM/YYYY HH:MM AM/PM"""
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    if _is_blank(value):
        return None
    text = _as_text(value)
    try:
        return datetime.strptime(text, APP_DATETIME_FORMAT)
    except ValueError:
        return None


def parse_filter_datetime(value, end_of_day=False):
    if value is None or _is_blank(value):
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    parsed = parse_app_datetime(value)
    if parsed is not None:
        return parsed
    try:
        parsed = datetime.strptime(_as_text(value), "%d/%m/%Y")
    except ValueError as error:
        raise ValueError(
            "Filter dates must use DD/MM/YYYY or DD/MM/YYYY HH:MM AM/PM."
        ) from error
    if end_of_day:
        return parsed.replace(hour=23, minute=59, second=59)
    return parsed


def expected_priority(severity, urgency):
    if severity not in SEVERITY_LEVELS or urgency not in URGENCY_LEVELS:
        raise ValueError("Severity and urgency must be valid before scoring.")
    return SEVERITY_LEVELS.index(severity) + 1 + URGENCY_LEVELS.index(urgency) + 1


def to_int_priority(value):
    if _is_blank(value):
        raise ValueError("Priority score is missing.")
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError) as error:
        raise ValueError("Priority score must be a whole number.") from error
    if number != int(number):
        raise ValueError("Priority score must be a whole number.")
    return int(number)


def serialize_incidents(incidents, allow_invalid=False):
    rows = []
    for item in incidents:
        if hasattr(item, "to_dict"):
            record = item.to_dict()
        elif isinstance(item, dict):
            record = item
        else:
            raise TypeError("Each incident must be a dictionary or Incident.")
        row = {}
        for field in INCIDENT_FIELDS:
            value = record.get(field, "")
            if field == "priority_score":
                try:
                    row[field] = to_int_priority(value)
                except ValueError:
                    if not allow_invalid:
                        raise
                    row[field] = "" if _is_blank(value) else value
            else:
                row[field] = _as_text(value)
        rows.append(row)
    return rows


def serialize_actions(actions):
    rows = []
    for item in actions:
        if not isinstance(item, dict):
            raise TypeError("Each action must be a dictionary.")
        rows.append({field: _as_text(item.get(field, "")) for field in ACTION_FIELDS})
    return rows


def records_to_dataframe(records, fields=INCIDENT_FIELDS):
    """Convert records for analysis"""
    rows = []
    for item in records:
        if hasattr(item, "to_dict"):
            record = item.to_dict()
        elif isinstance(item, dict):
            record = item
        else:
            raise TypeError("Each incident must be a dictionary or Incident.")
        row = {}
        for field in fields:
            value = record.get(field, "")
            if field == "priority_score":
                try:
                    row[field] = to_int_priority(value)
                except ValueError:
                    row[field] = "" if _is_blank(value) else value
            else:
                row[field] = _as_text(value)
        rows.append(row)
    return pd.DataFrame(rows, columns=list(fields))


def incidents_from_records(records):
    objects = []
    for record in serialize_incidents(records):
        objects.append(Incident(**{field: record[field] for field in INCIDENT_FIELDS}))
    return objects


def _read_table(path, fields):
    path = Path(path)
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, list):
                raise StorageError(path.name + " must contain a JSON list.")
            frame = pd.DataFrame(raw)
        elif suffix in {".csv", ".txt"}:
            frame = pd.read_csv(
                path, dtype=str, keep_default_na=False, encoding="utf-8"
            )
        else:
            raise StorageError("Supported data files are CSV and JSON.")
    except json.JSONDecodeError as error:
        raise StorageError("The file is not valid JSON: " + path.name) from error
    except pd.errors.EmptyDataError:
        frame = pd.DataFrame(columns=list(fields))
    except OSError as error:
        raise StorageError("Could not read " + path.name + ".") from error

    for field in fields:
        if field not in frame.columns:
            frame[field] = ""
    frame = frame.loc[:, list(fields)]
    for field in fields:
        if field != "priority_score":
            frame[field] = frame[field].map(_as_text)
    return frame


def _atomic_write_csv(frame, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    try:
        frame.to_csv(tmp, index=False, encoding="utf-8")
        tmp.replace(path)
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise


def _atomic_write_json(records, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(
            json.dumps(records, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(path)
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise


class DataRepository:

    def __init__(self, data_dir=None):
        self.data_dir = Path(data_dir) if data_dir is not None else DEFAULT_DATA_DIR
        self.incidents_path = self.data_dir / "incidents.csv"
        self.actions_path = self.data_dir / "incident_actions.csv"
        self.articles_path = self.data_dir / "articles.json"
        self.quiz_questions_path = self.data_dir / "quiz_questions.json"
        self.quiz_results_path = self.data_dir / "quiz_results.csv"

    def _prepare_empty_file(self, path, fields, json_file=False):
        path.parent.mkdir(parents=True, exist_ok=True)
        if json_file:
            _atomic_write_json([], path)
        else:
            _atomic_write_csv(pd.DataFrame(columns=list(fields)), path)

    def _load_records(self, path, fields, json_file=False):
        if not path.exists():
            self._prepare_empty_file(path, fields, json_file=json_file)
            return []
        try:
            frame = _read_table(path, fields)
        except StorageError:
            raise
        except Exception as error:
            raise StorageError("Could not read " + path.name + ".") from error
        records = frame.to_dict(orient="records")
        if "priority_score" in fields:
            normalized = []
            for record in records:
                if not _is_blank(record.get("priority_score")):
                    record["priority_score"] = to_int_priority(record["priority_score"])
                else:
                    record["priority_score"] = ""
                normalized.append(record)
            return normalized
        return records

    def load_incidents(self, path=None):
        target = Path(path) if path is not None else self.incidents_path
        return self._load_records(
            target, INCIDENT_FIELDS, json_file=target.suffix.lower() == ".json"
        )

    def save_incidents(self, incidents, path=None, allow_invalid=False):
        target = Path(path) if path is not None else self.incidents_path
        rows = serialize_incidents(incidents, allow_invalid=allow_invalid)
        frame = pd.DataFrame(rows, columns=list(INCIDENT_FIELDS))
        try:
            if target.suffix.lower() == ".json":
                _atomic_write_json(rows, target)
            else:
                _atomic_write_csv(frame, target)
        except OSError as error:
            raise StorageError("Could not save incidents.") from error
        return target

    def load_actions(self, path=None):
        target = Path(path) if path is not None else self.actions_path
        return self._load_records(
            target, ACTION_FIELDS, json_file=target.suffix.lower() == ".json"
        )

    def save_actions(self, actions, path=None):
        target = Path(path) if path is not None else self.actions_path
        rows = serialize_actions(actions)
        frame = pd.DataFrame(rows, columns=list(ACTION_FIELDS))
        try:
            if target.suffix.lower() == ".json":
                _atomic_write_json(rows, target)
            else:
                _atomic_write_csv(frame, target)
        except OSError as error:
            raise StorageError("Could not save actions.") from error
        return target

    def load_articles(self, path=None):
        target = Path(path) if path is not None else self.articles_path
        return self._load_records(target, ARTICLE_FIELDS, json_file=True)

    def save_articles(self, articles, path=None):
        target = Path(path) if path is not None else self.articles_path
        rows = []
        for item in articles:
            if not isinstance(item, dict):
                raise TypeError("Each article must be a dictionary.")
            rows.append({field: item.get(field, "") for field in ARTICLE_FIELDS})
        try:
            if target.suffix.lower() == ".json":
                _atomic_write_json(rows, target)
            else:
                _atomic_write_csv(
                    pd.DataFrame(rows, columns=list(ARTICLE_FIELDS)), target
                )
        except OSError as error:
            raise StorageError("Could not save articles.") from error
        return target

    def load_quiz_questions(self, path=None):
        target = Path(path) if path is not None else self.quiz_questions_path
        if not target.exists():
            self._prepare_empty_file(target, QUIZ_QUESTION_FIELDS, json_file=True)
            return []
        try:
            raw = json.loads(target.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise StorageError("The file is not valid JSON: " + target.name) from error
        if not isinstance(raw, list):
            raise StorageError(target.name + " must contain a JSON list.")
        return raw

    def save_quiz_questions(self, questions, path=None):
        target = Path(path) if path is not None else self.quiz_questions_path
        if not isinstance(questions, list):
            raise TypeError("Quiz questions must be a list.")
        try:
            _atomic_write_json(questions, target)
        except OSError as error:
            raise StorageError("Could not save quiz questions.") from error
        return target

    def load_quiz_results(self, path=None):
        target = Path(path) if path is not None else self.quiz_results_path
        records = self._load_records(
            target, QUIZ_RESULT_FIELDS, json_file=target.suffix.lower() == ".json"
        )
        for record in records:
            if not _is_blank(record.get("score")):
                record["score"] = int(float(record["score"]))
            if not _is_blank(record.get("total_questions")):
                record["total_questions"] = int(float(record["total_questions"]))
        return records

    def save_quiz_results(self, results, path=None):
        target = Path(path) if path is not None else self.quiz_results_path
        rows = []
        for item in results:
            if not isinstance(item, dict):
                raise TypeError("Each quiz result must be a dictionary.")
            row = {field: item.get(field, "") for field in QUIZ_RESULT_FIELDS}
            row["result_id"] = _as_text(row["result_id"])
            row["participant_code"] = _as_text(row["participant_code"])
            row["quiz_stage"] = _as_text(row["quiz_stage"])
            row["quiz_date"] = _as_text(row["quiz_date"])
            row["score"] = int(row["score"])
            row["total_questions"] = int(row["total_questions"])
            rows.append(row)
        frame = pd.DataFrame(rows, columns=list(QUIZ_RESULT_FIELDS))
        try:
            if target.suffix.lower() == ".json":
                _atomic_write_json(rows, target)
            else:
                _atomic_write_csv(frame, target)
        except OSError as error:
            raise StorageError("Could not save quiz results.") from error
        return target

    def export_incidents(self, incidents, path):
        return self.save_incidents(incidents, path)


class IncidentAnalyzer:
    """Clean incident records and calculate dashboard KPIs with Pandas"""

    def __init__(self, repository=None):
        self.repository = repository

    def _to_frame(self, records=None):
        if records is None:
            if self.repository is None:
                raise ValueError("No incident records were provided.")
            records = self.repository.load_incidents()
        if isinstance(records, pd.DataFrame):
            frame = records.copy()
            for field in INCIDENT_FIELDS:
                if field not in frame.columns:
                    frame[field] = ""
            return frame.loc[:, list(INCIDENT_FIELDS)]
        return records_to_dataframe(records)

    def _datetime_series(self, series):
        parsed = [parse_app_datetime(value) for value in series]
        return pd.Series(
            [pd.Timestamp(value) if value is not None else pd.NaT for value in parsed],
            index=series.index,
        )

    def clean_data(self, records=None):
        """Clean missing values, duplicates, and invalid dates

        same incident_id. The first row is kept
        Invalid reported_at rows are dropped so review-time math is not wrong
        """
        frame = self._to_frame(records)
        report = {
            "rows_in": int(len(frame)),
            "rows_out": 0,
            "dropped_empty_rows": 0,
            "dropped_missing_required": 0,
            "dropped_invalid_id": 0,
            "dropped_invalid_dates": 0,
            "dropped_invalid_category": 0,
            "dropped_invalid_status": 0,
            "dropped_invalid_severity": 0,
            "dropped_invalid_urgency": 0,
            "dropped_invalid_scope": 0,
            "dropped_duplicate_ids": 0,
            "priority_recalculated": 0,
            "cleared_invalid_reviewed_at": 0,
            "excluded_negative_review_times": 0,
        }

        if frame.empty:
            report["rows_out"] = 0
            return frame.reset_index(drop=True), report

        working = frame.copy()
        for field in INCIDENT_FIELDS:
            if field != "priority_score":
                working[field] = working[field].map(_as_text)

        empty_mask = working.apply(
            lambda row: all(_is_blank(value) for value in row), axis=1
        )
        report["dropped_empty_rows"] = int(empty_mask.sum())
        working = working.loc[~empty_mask].copy()

        required_blank = pd.Series(False, index=working.index)
        for field in REQUIRED_INCIDENT_FIELDS:
            required_blank = required_blank | working[field].map(_is_blank)
        report["dropped_missing_required"] = int(required_blank.sum())
        working = working.loc[~required_blank].copy()

        invalid_id = ~working["incident_id"].map(
            lambda value: bool(INCIDENT_ID_PATTERN.match(value))
        )
        report["dropped_invalid_id"] = int(invalid_id.sum())
        working = working.loc[~invalid_id].copy()

        reported = self._datetime_series(working["reported_at"])
        invalid_reported = reported.isna()
        report["dropped_invalid_dates"] = int(invalid_reported.sum())
        working = working.loc[~invalid_reported].copy()
        reported = reported.loc[~invalid_reported]
        working["reported_at"] = [
            format_app_datetime(value.to_pydatetime()) for value in reported
        ]

        reviewed = self._datetime_series(working["reviewed_at"])
        invalid_reviewed = (
            working["reviewed_at"].map(lambda value: not _is_blank(value))
            & reviewed.isna()
        )
        report["cleared_invalid_reviewed_at"] = int(invalid_reviewed.sum())
        working.loc[invalid_reviewed, "reviewed_at"] = ""
        reviewed.loc[invalid_reviewed] = pd.NaT
        formatted_reviewed = []
        for value in reviewed:
            if pd.isna(value):
                formatted_reviewed.append("")
            else:
                formatted_reviewed.append(format_app_datetime(value.to_pydatetime()))
        working["reviewed_at"] = formatted_reviewed

        invalid_category = ~working["category"].isin(CATEGORIES)
        report["dropped_invalid_category"] = int(invalid_category.sum())
        working = working.loc[~invalid_category].copy()

        invalid_status = ~working["status"].isin(STATUSES)
        report["dropped_invalid_status"] = int(invalid_status.sum())
        working = working.loc[~invalid_status].copy()

        invalid_severity = ~working["severity"].isin(SEVERITY_LEVELS)
        report["dropped_invalid_severity"] = int(invalid_severity.sum())
        working = working.loc[~invalid_severity].copy()

        invalid_urgency = ~working["urgency"].isin(URGENCY_LEVELS)
        report["dropped_invalid_urgency"] = int(invalid_urgency.sum())
        working = working.loc[~invalid_urgency].copy()

        invalid_scope = ~working["affected_scope"].isin(AFFECTED_SCOPES)
        report["dropped_invalid_scope"] = int(invalid_scope.sum())
        working = working.loc[~invalid_scope].copy()

        priorities = []
        recalculated = 0
        for _, row in working.iterrows():
            expected = expected_priority(row["severity"], row["urgency"])
            try:
                current = to_int_priority(row["priority_score"])
            except ValueError:
                current = expected
                recalculated += 1
            if current != expected:
                current = expected
                recalculated += 1
            priorities.append(int(current))
        working["priority_score"] = priorities
        report["priority_recalculated"] = recalculated

        duplicate_count = int(working["incident_id"].duplicated(keep="first").sum())
        report["dropped_duplicate_ids"] = duplicate_count
        working = working.drop_duplicates(subset=["incident_id"], keep="first")

        working["resolution"] = working["resolution"].map(_as_text)
        working = working.reset_index(drop=True)
        report["rows_out"] = int(len(working))
        return working, report

    def apply_filters(self, frame, filters=None):
        if frame.empty:
            return frame.copy()
        filters = filters or {}
        selected = frame.copy()
        reported = self._datetime_series(selected["reported_at"])

        date_from = parse_filter_datetime(filters.get("date_from"))
        date_to = parse_filter_datetime(filters.get("date_to"), end_of_day=True)
        if date_from is not None:
            selected = selected.loc[reported >= pd.Timestamp(date_from)]
            reported = reported.loc[selected.index]
        if date_to is not None:
            selected = selected.loc[reported <= pd.Timestamp(date_to)]

        for field, key in (
            ("category", "categories"),
            ("status", "statuses"),
            ("severity", "severities"),
        ):
            values = filters.get(key)
            if values:
                selected = selected.loc[selected[field].isin(list(values))]
        return selected.reset_index(drop=True)

    def group_by_category(self, frame):
        if frame.empty:
            return pd.DataFrame(columns=["category", "count"])
        return (
            frame.groupby("category", dropna=False)
            .size()
            .reset_index(name="count")
            .sort_values(["count", "category"], ascending=[False, True])
            .reset_index(drop=True)
        )

    def group_by_status(self, frame):
        if frame.empty:
            return pd.DataFrame(columns=["status", "count"])
        counts = (
            frame.groupby("status", dropna=False)
            .size()
            .reindex(list(STATUSES), fill_value=0)
            .reset_index(name="count")
        )
        counts.columns = ["status", "count"]
        return counts

    def group_by_severity(self, frame):
        if frame.empty:
            return pd.DataFrame(columns=["severity", "count"])
        counts = (
            frame.groupby("severity", dropna=False)
            .size()
            .reindex(list(SEVERITY_LEVELS), fill_value=0)
            .reset_index(name="count")
        )
        counts.columns = ["severity", "count"]
        return counts

    def analyze_trends(self, frame, freq="M"):
        empty = pd.DataFrame(columns=["period", "count"])
        if frame.empty:
            return empty
        reported = self._datetime_series(frame["reported_at"]).dropna()
        if reported.empty:
            return empty
        if freq == "D":
            grouped = reported.dt.floor("D")
            trend = grouped.value_counts().sort_index()
            result = trend.reset_index()
            result.columns = ["period_dt", "count"]
            result["period"] = result["period_dt"].dt.strftime("%d/%m/%Y")
            return result[["period", "count"]]
        if freq == "W":
            periods = reported.dt.to_period("W").astype(str)
        else:
            periods = reported.dt.to_period("M").astype(str)
        trend = periods.value_counts().sort_index()
        result = trend.reset_index()
        result.columns = ["period", "count"]
        return result

    def _review_hours(self, frame):
        if frame.empty:
            return pd.Series(dtype="float64"), 0
        reported = self._datetime_series(frame["reported_at"])
        reviewed = self._datetime_series(frame["reviewed_at"])
        usable = reported.notna() & reviewed.notna()
        hours = (
            reviewed.loc[usable] - reported.loc[usable]
        ).dt.total_seconds() / 3600.0
        negative = int((hours < 0).sum())
        hours = hours.loc[hours >= 0]
        return hours, negative

    def calculate_metrics(self, frame):
        total = int(len(frame))
        unresolved = (
            int(frame["status"].isin(UNRESOLVED_STATUSES).sum()) if total else 0
        )
        hours, negative = self._review_hours(frame)
        average_hours = round(float(hours.mean()), 2) if not hours.empty else None
        return {
            "total_incidents": total,
            "unresolved_incidents": unresolved,
            "unresolved_percent": (
                round((unresolved / total) * 100, 2) if total else None
            ),
            "average_review_hours": average_hours,
            "reviewed_with_timestamp": int(len(hours)),
            "excluded_negative_review_times": negative,
        }

    def clean_quiz_results(self, results=None):
        if results is None:
            if self.repository is None:
                return pd.DataFrame(columns=list(QUIZ_RESULT_FIELDS)), {
                    "rows_in": 0,
                    "rows_out": 0,
                }
            results = self.repository.load_quiz_results()
        if isinstance(results, pd.DataFrame):
            frame = results.copy()
        else:
            frame = pd.DataFrame(results)
        for field in QUIZ_RESULT_FIELDS:
            if field not in frame.columns:
                frame[field] = ""
        frame = frame.loc[:, list(QUIZ_RESULT_FIELDS)]
        report = {"rows_in": int(len(frame)), "rows_out": 0, "dropped_invalid": 0}
        if frame.empty:
            return frame, report

        keep = []
        for _, row in frame.iterrows():
            valid = True
            if not RESULT_ID_PATTERN.match(_as_text(row["result_id"])):
                valid = False
            if _is_blank(row["participant_code"]):
                valid = False
            if _as_text(row["quiz_stage"]) not in QUIZ_STAGES:
                valid = False
            if parse_app_datetime(row["quiz_date"]) is None:
                valid = False
            try:
                score = int(float(row["score"]))
                total = int(float(row["total_questions"]))
            except (TypeError, ValueError):
                valid = False
                score = 0
                total = 0
            if valid and (total <= 0 or score < 0 or score > total):
                valid = False
            keep.append(valid)
        cleaned = frame.loc[keep].copy()
        if not cleaned.empty:
            cleaned["score"] = cleaned["score"].map(lambda value: int(float(value)))
            cleaned["total_questions"] = cleaned["total_questions"].map(
                lambda value: int(float(value))
            )
            cleaned["quiz_stage"] = cleaned["quiz_stage"].map(_as_text)
            cleaned["quiz_date"] = [
                format_app_datetime(parse_app_datetime(value))
                for value in cleaned["quiz_date"]
            ]
        report["dropped_invalid"] = int((~pd.Series(keep)).sum())
        report["rows_out"] = int(len(cleaned))
        return cleaned.reset_index(drop=True), report

    def _quiz_metrics(self, quiz_results):
        frame, report = self.clean_quiz_results(quiz_results)
        empty = pd.DataFrame(columns=["quiz_stage", "average_score", "attempts"])
        if frame.empty:
            return {
                "average_quiz_score": None,
                "attempts": 0,
                "by_stage": empty,
                "cleaning_report": report,
            }
        percent = (frame["score"] / frame["total_questions"]) * 100
        by_stage = (
            frame.assign(percent=percent)
            .groupby("quiz_stage", dropna=False)["percent"]
            .agg(["mean", "size"])
            .reset_index()
        )
        by_stage.columns = ["quiz_stage", "average_score", "attempts"]
        by_stage["average_score"] = by_stage["average_score"].round(2)
        return {
            "average_quiz_score": round(float(percent.mean()), 2),
            "attempts": int(len(frame)),
            "by_stage": by_stage,
            "cleaning_report": report,
        }

    def _insights(self, frame, kpis, quiz_metrics):
        if frame.empty:
            return [
                "No incidents match the selected filters.",
            ]
        insights = []
        by_category = self.group_by_category(frame)
        top = by_category.iloc[0]
        insights.append(
            f"{top['category']} is the most reported category in the filtered dataset "
            f"({int(top['count'])} of {kpis['total_incidents']} reports, "
            f"{round((int(top['count']) / kpis['total_incidents']) * 100, 1)}%)."
        )
        unresolved = kpis["unresolved_incidents"]
        percent = kpis["unresolved_percent"]
        insights.append(
            f"{unresolved} reports are unresolved (Submitted or Under Review"
            + (
                f", {percent}% of the filtered dataset)."
                if percent is not None
                else ")."
            )
        )
        if kpis["average_review_hours"] is None:
            insights.append(
                "Average review time is not available because no filtered report has a valid review timestamp."
            )
        else:
            insights.append(
                f"Average time from submission to first recorded review is "
                f"{kpis['average_review_hours']} hours "
                f"({kpis['reviewed_with_timestamp']} reports with a valid review timestamp)."
            )
        trend = self.analyze_trends(frame, freq="M")
        if not trend.empty:
            peak = trend.sort_values("count", ascending=False).iloc[0]
            insights.append(
                f"The month with the most reports in this filter is {peak['period']} "
                f"({int(peak['count'])} reports)."
            )
        if quiz_metrics["attempts"]:
            insights.append(
                f"Average quiz score is {quiz_metrics['average_quiz_score']}% "
                f"across {quiz_metrics['attempts']} attempts. "
                "A score change is not proof that real-world incidents decreased."
            )
        return insights

    def get_dashboard_metrics(
        self, records=None, filters=None, quiz_results=None, trend_freq="M"
    ):
        cleaned, cleaning_report = self.clean_data(records)
        filtered = self.apply_filters(cleaned, filters)
        kpis = self.calculate_metrics(filtered)
        quiz_metrics = self._quiz_metrics(quiz_results)
        empty_message = ""
        if filtered.empty:
            empty_message = "No incidents match the selected filters."
        return {
            "kpis": kpis,
            "by_category": self.group_by_category(filtered),
            "by_status": self.group_by_status(filtered),
            "by_severity": self.group_by_severity(filtered),
            "trend": self.analyze_trends(filtered, freq=trend_freq),
            "recurring_categories": self.group_by_category(filtered),
            "quiz": quiz_metrics,
            "insights": self._insights(filtered, kpis, quiz_metrics),
            "is_empty": bool(filtered.empty),
            "message": empty_message,
            "cleaning_report": cleaning_report,
            "filters_applied": filters or {},
            "filtered_incidents": filtered,
        }

    def export_summary(self, metrics, path):
        kpis = metrics["kpis"]
        rows = [
            {"metric": "total_incidents", "value": kpis["total_incidents"]},
            {"metric": "unresolved_incidents", "value": kpis["unresolved_incidents"]},
            {"metric": "unresolved_percent", "value": kpis["unresolved_percent"]},
            {"metric": "average_review_hours", "value": kpis["average_review_hours"]},
            {
                "metric": "reviewed_with_timestamp",
                "value": kpis["reviewed_with_timestamp"],
            },
            {
                "metric": "average_quiz_score",
                "value": metrics["quiz"]["average_quiz_score"],
            },
        ]
        _atomic_write_csv(pd.DataFrame(rows), path)
        return Path(path)


DESCRIPTION_TEMPLATES = {
    "Phishing / Suspicious Message": (
        "[SIMULATED] A message claimed to be from campus IT and asked the user to confirm a student portal password on an unfamiliar page.",
        "[SIMULATED] An email used the university name and asked the recipient to click a button to prevent mailbox closure.",
        "[SIMULATED] A chat message offered a scholarship form and asked for a login code. No live link was opened.",
        "[SIMULATED] A notice said a library fine must be paid immediately through a page that did not match the usual library address.",
        "[SIMULATED] A message impersonated a lecturer and asked students to share a one-time sign-in code.",
    ),
    "Account Security": (
        "[SIMULATED] The user received a login alert for a campus account from an unrecognized city.",
        "[SIMULATED] Password reset emails arrived repeatedly although the user did not request a reset.",
        "[SIMULATED] A shared lab computer still had a previous student session open.",
        "[SIMULATED] Multi-factor prompts appeared at night when the user was not signing in.",
        "[SIMULATED] An old personal email still listed as the account recovery address looked unused.",
    ),
    "Malware": (
        "[SIMULATED] A coursework file from a classmate triggered a browser warning before it was opened.",
        "[SIMULATED] A USB classroom file installer asked for permission to run an unknown program. It was not run.",
        "[SIMULATED] A downloaded notes archive had a double file extension that did not match a normal document.",
        "[SIMULATED] A pop-up claimed the laptop was infected and demanded a call to a support number.",
        "[SIMULATED] An email attachment named invoice.pdf.exe was reported and not opened.",
    ),
    "Unauthorized Access": (
        "[SIMULATED] Coursework files in a shared folder were renamed overnight without a known editor.",
        "[SIMULATED] A lab account showed last-access times outside booked hours.",
        "[SIMULATED] An unknown device appeared in the campus account session list.",
        "[SIMULATED] A shared department mailbox sent mail that the usual owners did not write.",
        "[SIMULATED] A locker-room camera account password was still the default word from setup notes.",
    ),
    "Other": (
        "[SIMULATED] A public Wi-Fi hotspot at a cafe asked the user to install a certificate to continue.",
        "[SIMULATED] A caller claimed to be from campus finance and asked for a one-time payment code.",
        "[SIMULATED] A social-media page copied the student union name and asked for event registration details.",
        "[SIMULATED] A QR poster on a noticeboard pointed to a shortened address that did not match the official site. It was not opened.",
        "[SIMULATED] A job offer chat asked for copies of a national ID photo before any interview.",
    ),
}

RESOLUTION_TEMPLATES = (
    "Synthetic review: user advised not to open the message and to keep the original report. Not a confirmed attack.",
    "Synthetic review: password reset and MFA check were recommended. No live investigation was performed.",
    "Synthetic review: report classified for awareness follow-up. Priority score is not a decision that an attack occurred.",
    "Synthetic review: closed after guidance was recorded. Dataset row is simulated.",
)


def generate_synthetic_incidents(count=500, seed=SYNTHETIC_SEED):
    rng = random.Random(seed)
    start = datetime(2026, 5, 4, 8, 15)
    latest_report = datetime(2026, 10, 12, 16, 40)
    span_seconds = int((latest_report - start).total_seconds())
    incidents = []
    actions = []
    action_number = 1

    for index in range(count):
        reported = start + timedelta(seconds=rng.randint(0, span_seconds))
        reported = reported.replace(second=0, microsecond=0)
        category = rng.choices(
            CATEGORIES,
            weights=(40, 20, 15, 15, 10),
            k=1,
        )[0]
        severity = rng.choices(SEVERITY_LEVELS, weights=(20, 40, 30, 10), k=1)[0]
        urgency = rng.choices(URGENCY_LEVELS, weights=(30, 45, 25), k=1)[0]
        scope = rng.choices(AFFECTED_SCOPES, weights=(45, 30, 15, 10), k=1)[0]
        status = rng.choices(STATUSES, weights=(22, 28, 35, 15), k=1)[0]
        description = rng.choice(DESCRIPTION_TEMPLATES[category])
        incident_id = "INC-" + str(1001 + index)
        reviewed_at = ""
        resolution = ""
        reviewed_time = None

        if status != "Submitted":
            delay_minutes = rng.randint(20, 48 * 60)
            reviewed_time = reported + timedelta(minutes=delay_minutes)
            if reviewed_time > datetime(2026, 10, 13, 12, 0):
                reviewed_time = datetime(2026, 10, 13, 12, 0)
            if reviewed_time <= reported:
                reviewed_time = reported + timedelta(minutes=25)
            reviewed_time = reviewed_time.replace(second=0, microsecond=0)
            reviewed_at = format_app_datetime(reviewed_time)
            actions.append(
                {
                    "action_id": "ACT-" + str(action_number).zfill(4),
                    "incident_id": incident_id,
                    "action_type": "Status changed: Submitted -> Under Review",
                    "action_time": reviewed_at,
                    "note": "Synthetic review started. No live suspicious link was opened.",
                }
            )
            action_number += 1

        if status in {"Resolved", "Closed"} and reviewed_time is not None:
            close_time = reviewed_time + timedelta(minutes=rng.randint(30, 36 * 60))
            if close_time > datetime(2026, 10, 13, 16, 0):
                close_time = datetime(2026, 10, 13, 16, 0)
            if close_time <= reviewed_time:
                close_time = reviewed_time + timedelta(minutes=35)
            close_time = close_time.replace(second=0, microsecond=0)
            close_stamp = format_app_datetime(close_time)
            if status == "Resolved":
                resolution = rng.choice(RESOLUTION_TEMPLATES)
                action_type = "Status changed: Under Review -> Resolved"
                note = "Synthetic resolution recorded for demonstration."
            else:
                action_type = "Status changed: Under Review -> Closed"
                note = "Synthetic closure recorded for demonstration."
            actions.append(
                {
                    "action_id": "ACT-" + str(action_number).zfill(4),
                    "incident_id": incident_id,
                    "action_type": action_type,
                    "action_time": close_stamp,
                    "note": note,
                }
            )
            action_number += 1

        incidents.append(
            {
                "incident_id": incident_id,
                "reported_at": format_app_datetime(reported),
                "category": category,
                "description": description,
                "severity": severity,
                "urgency": urgency,
                "affected_scope": scope,
                "priority_score": expected_priority(severity, urgency),
                "status": status,
                "reviewed_at": reviewed_at,
                "resolution": resolution,
            }
        )
    return incidents, actions


def generate_synthetic_quiz_results(participant_count=40, seed=SYNTHETIC_SEED):
    rng = random.Random(seed + 7)
    results = []
    result_number = 1
    start = datetime(2026, 6, 1, 9, 0)
    for index in range(participant_count):
        participant = "P-" + str(index + 1).zfill(4)
        pre_date = start + timedelta(days=rng.randint(0, 40), hours=rng.randint(0, 8))
        post_date = pre_date + timedelta(
            days=rng.randint(5, 20), hours=rng.randint(0, 5)
        )
        pre_score = rng.randint(3, 7)
        post_score = min(10, pre_score + rng.randint(0, 4))
        for stage, score, when in (
            ("pre-training", pre_score, pre_date),
            ("post-training", post_score, post_date),
        ):
            results.append(
                {
                    "result_id": "RES-" + str(result_number).zfill(4),
                    "participant_code": participant,
                    "quiz_stage": stage,
                    "quiz_date": format_app_datetime(
                        when.replace(second=0, microsecond=0)
                    ),
                    "score": score,
                    "total_questions": 10,
                }
            )
            result_number += 1
    return results


def generate_dirty_incidents():
    """Rows used only to prove cleaning. Do not load this file into IncidentManager."""
    valid = {
        "incident_id": "INC-9001",
        "reported_at": "01/09/2026 10:00 AM",
        "category": "Phishing / Suspicious Message",
        "description": "[SIMULATED] Valid dirty-set control row.",
        "severity": "High",
        "urgency": "Medium",
        "affected_scope": "One user",
        "priority_score": 5,
        "status": "Submitted",
        "reviewed_at": "",
        "resolution": "",
    }
    rows = [
        valid,
        dict(valid),
        {
            **valid,
            "incident_id": "INC-9002",
            "reported_at": "2026-09-01",
            "description": "[SIMULATED] Invalid ISO date on purpose.",
        },
        {
            **valid,
            "incident_id": "INC-9003",
            "description": "",
        },
        {
            **valid,
            "incident_id": "INC-9004",
            "category": "Hacking",
            "description": "[SIMULATED] Invalid category on purpose.",
        },
        {
            **valid,
            "incident_id": "INC-9005",
            "priority_score": 99,
            "severity": "Low",
            "urgency": "Low",
            "description": "[SIMULATED] Wrong priority on purpose.",
        },
        {
            **valid,
            "incident_id": "INC-9006",
            "status": "Done",
            "description": "[SIMULATED] Invalid status on purpose.",
        },
        {
            **valid,
            "incident_id": "",
            "description": "[SIMULATED] Missing ID on purpose.",
        },
        {
            **valid,
            "incident_id": "INC-9008",
            "status": "Under Review",
            "reviewed_at": "not-a-date",
            "description": "[SIMULATED] Invalid review timestamp on purpose.",
            "priority_score": 5,
        },
        {field: "" for field in INCIDENT_FIELDS},
    ]
    return rows


def generate_and_save_synthetic_dataset(data_dir=None, incident_count=500):
    repository = DataRepository(data_dir)
    repository.data_dir.mkdir(parents=True, exist_ok=True)
    incidents, actions = generate_synthetic_incidents(incident_count)
    quiz_results = generate_synthetic_quiz_results()
    dirty = generate_dirty_incidents()

    repository.save_incidents(incidents)
    repository.save_incidents(incidents, repository.data_dir / "incidents.json")
    repository.save_actions(actions)
    repository.save_actions(actions, repository.data_dir / "incident_actions.json")
    repository.save_quiz_results(quiz_results)
    repository.save_quiz_results(
        quiz_results, repository.data_dir / "quiz_results.json"
    )
    repository.save_incidents(
        dirty,
        repository.data_dir / "dirty_incidents.csv",
        allow_invalid=True,
    )
    repository.save_articles([])
    repository.save_quiz_questions([])
    return {
        "incidents": len(incidents),
        "actions": len(actions),
        "quiz_results": len(quiz_results),
        "dirty_incidents": len(dirty),
        "data_dir": str(repository.data_dir),
    }


def print_analytics_preview(data_dir=None):
    repository = DataRepository(data_dir)
    analyzer = IncidentAnalyzer(repository)
    incidents = repository.load_incidents()
    quiz_results = repository.load_quiz_results()
    metrics = analyzer.get_dashboard_metrics(incidents, quiz_results=quiz_results)
    kpis = metrics["kpis"]
    print("CyberAware analytics preview (synthetic data)")
    print("Total incidents:", kpis["total_incidents"])
    print("Unresolved:", kpis["unresolved_incidents"], kpis["unresolved_percent"])
    print("Average review hours:", kpis["average_review_hours"])
    print("By category:")
    print(metrics["by_category"].to_string(index=False))
    print("Insights:")
    for line in metrics["insights"]:
        print("-", line)


if __name__ == "__main__":
    summary = generate_and_save_synthetic_dataset()
    print("Wrote synthetic dataset:", summary)
    print_analytics_preview(summary["data_dir"])
