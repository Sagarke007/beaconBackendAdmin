"""
Database utility functions for reading and writing JSON data.
"""

import json
import os


def read_data(file_path):
    """Reads data from a JSON file."""
    if not os.path.exists(file_path):
        return {"users": {}}
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_data(data, file_path):
    """Writes data to a JSON file."""
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
