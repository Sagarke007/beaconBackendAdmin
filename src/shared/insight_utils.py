"""
This module provides utility functions to extract and process project information for insights.
"""

from collections import defaultdict
import numpy as np
import json
from datetime import datetime
from pathlib import Path

from shared.database import read_data


PROJECTS_FILE = "projects.json"
LOCAL_DIR = Path("../health_data")


def project_information(user_id: str):
    """
    Function to fetch project information for a given user ID.
    It reads the data from the specified JSON files and processes it to extract relevant details.
    """
    # Read the data file
    data = read_data(PROJECTS_FILE)
    projects = data["users"].get(user_id, {}).get("projects", [])

    project_details = []

    for project in projects:
        project_id = project.get("project_id")
        dsn = project.get("dsn", "")
        endpoint_file_path = LOCAL_DIR / "api_endpoint" / user_id / f"{project_id}.json"
        log_file_path = LOCAL_DIR / "api_log" / user_id / f"{project_id}.json"

        framework = ""
        average_response_time = "0 sec"
        api_count = 0
        datewise_counts = defaultdict(lambda: {"2xx": 0, "4xx": 0, "5xx": 0})

        # Endpoint stats (response time, framework, count)
        if endpoint_file_path.exists():
            try:
                project_data = read_data(endpoint_file_path)
                apis = project_data.get("endpoints", [])
                if apis:
                    total_response_time = sum(
                        api.get("response_time", 0) for api in apis
                    )
                    api_count = len(apis)
                    framework = apis[-1].get("framework", "FastApi")
                    average_response_time = (
                        f"{round(total_response_time / api_count, 4)} sec"
                    )
            except (FileNotFoundError, json.JSONDecodeError):
                pass

        # Log summary (date-wise grouping)
        if log_file_path.exists():
            try:
                with open(log_file_path, "r", encoding="utf-8") as f:
                    log_entries = json.load(f)

                for entry in log_entries:
                    try:
                        status_code = int(entry.get("status_code", 0))
                        timestamp = entry.get("timestamp") or entry.get("time") or ""
                        if not timestamp:
                            continue
                        try:
                            dt = datetime.fromisoformat(timestamp)
                            date_str = dt.date().isoformat()
                        except ValueError:
                            continue  # Skip bad timestamp

                        if 200 <= status_code < 300:
                            datewise_counts[date_str]["2xx"] += 1
                        elif 400 <= status_code < 500:
                            datewise_counts[date_str]["4xx"] += 1
                        elif 500 <= status_code < 600:
                            datewise_counts[date_str]["5xx"] += 1
                    except (ValueError, KeyError):
                        continue
            except (FileNotFoundError, json.JSONDecodeError):
                pass

        # Convert to expected format
        seq_dates = sorted(datewise_counts.keys())
        datewise_summary = {
            "seq": seq_dates,
            "keys": ["2xx", "4xx", "5xx"],
            "rowData": {
                date: {
                    "2xx": datewise_counts[date]["2xx"],
                    "4xx": datewise_counts[date]["4xx"],
                    "5xx": datewise_counts[date]["5xx"],
                }
                for date in seq_dates
            },
        }

        # Assemble final project info
        project_details.append(
            {
                "projectName": project.get("name"),
                "projectPath": project.get("url"),
                "description": project.get("description"),
                "projectID": project_id,
                "framework": framework,
                "averageResponseTime": average_response_time,
                "dsn": dsn,
                "apiCount": api_count,
                "dateWiseSummary": datewise_summary,
            }
        )
    return project_details


def calculate_average_metrics_by_path(project_path):
    """
    Calculate average metrics for log entries, grouped by path.

    Args:
        log_entries (list): A list of dictionaries containing log details.

    Returns:
        dict: A dictionary where keys are paths and values are average metrics for each path.
    """
    log_entries = read_data(project_path)
    path_metrics = defaultdict(list)
    path_users = defaultdict(set)

    # Group process times and user_ids by path
    for entry in log_entries:
        path = entry.get("path", "/unknown")
        process_time = entry.get("process_time", 0.0)
        status_code = entry.get("status_code", 200)
        user_id = entry.get("user_id", None)

        # Store relevant data per path
        path_metrics[path].append(
            {"process_time": process_time, "status_code": status_code}
        )

        if user_id:
            path_users[path].add(user_id)

    data_store = []
    for path, entries in path_metrics.items():
        process_times = [e["process_time"] for e in entries]
        status_codes = [e["status_code"] for e in entries]

        count = len(entries)

        avg_tpm = sum(1.0 / pt for pt in process_times if pt > 0) / count
        p50 = np.percentile(process_times, 50)
        p95 = np.percentile(process_times, 95)
        failure_percent = (sum(1 for sc in status_codes if sc >= 400) / count) * 100
        apdex = sum(1 for pt in process_times if pt <= 0.5) / count
        api_hit_count = count

        data_store.append(
            {
                "Path": path,
                "TPM": round(avg_tpm, 3),
                "P50": f"{round(p50 * 1000, 2)} ms",
                "P95": f"{round(p95 * 1000, 2)} ms",
                "Failure %": f"{round(failure_percent, 2)}%",
                "APDEX": round(apdex, 3),
                "Requests Count": api_hit_count,
            }
        )

    return data_store
