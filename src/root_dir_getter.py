"""
Project root directory fetcher
"""

import sys
from pathlib import Path


def get_root_dir(sub_file: str) -> str:
    """
    Function to get the parent level of the root directory
    """
    paths = Path(sub_file).resolve().parents
    for path in paths:
        if Path.joinpath(path, "root_dir_setter").exists():
            return str(path)
    raise ValueError("Unable to find the project root dir setter")


def set_root_dir(sub_file: str) -> None:
    """Set to root directory of sub file in sys.path if necessary

    Args:
        sub_file (str): a file in root or a sub root directory
    """
    global ROOT_DIR
    ROOT_DIR = get_root_dir(sub_file)
    if ROOT_DIR not in sys.path:
        sys.path.insert(0, ROOT_DIR)
