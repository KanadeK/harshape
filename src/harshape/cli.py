"""CLI output includes only generated counts, not original names or values."""

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import DEFAULT_INPUT_BYTES, ShapeError, project_file


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a performance-only HAR skeleton with file-local URL pseudonyms."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="A new file; existing paths are never overwritten",
    )
    parser.add_argument("--max-input-bytes", type=int, default=DEFAULT_INPUT_BYTES)
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    try:
        print(
            json.dumps(
                project_file(args.input, args.output, max_input_bytes=args.max_input_bytes),
                sort_keys=True,
            )
        )
        return 0
    except (ShapeError, OSError) as exc:
        print("harshape: " + json.dumps(str(exc), ensure_ascii=True), file=sys.stderr)
        return 2
