"""A runnable synthetic capture: timings survive, private text does not."""

import json
import tempfile
from pathlib import Path

from harshape.core import project_file


def main():
    canary = "PRIVATE_DEMO_CANARY_8bcab1"
    entry = {
        "startedDateTime": "2026-01-05T09:00:00+08:00",
        "time": 120,
        "request": {
            "method": "GET",
            "url": f"https://private.example/user/{canary}?token={canary}",
            "httpVersion": "HTTP/2",
            "headers": [{"name": "Authorization", "value": canary}],
        },
        "response": {
            "status": 200,
            "httpVersion": "HTTP/2",
            "content": {"size": 64, "mimeType": "application/json", "text": canary},
        },
        "timings": {"send": 5, "wait": 100, "receive": 15},
        "_privateExtension": canary,
    }
    document = {"log": {"version": "1.2", "creator": {"name": canary}, "entries": [entry]}}
    with tempfile.TemporaryDirectory(prefix="harshape-demo-") as temp:
        root = Path(temp)
        source, target = root / "original.har", root / "share.har"
        source.write_text(json.dumps(document), encoding="utf-8")
        summary = project_file(source, target)
        serialized = target.read_text(encoding="utf-8")
        projected = json.loads(serialized)["log"]["entries"][0]
        if canary in serialized or "private.example" in serialized or projected["time"] != 120:
            raise RuntimeError(
                "Projection did not preserve the documented privacy/performance boundary"
            )
        if projected["startedDateTime"] != "2000-01-01T00:00:00.000000Z":
            raise RuntimeError("Original timestamp was not shifted")
        print(json.dumps(summary, indent=2))
        print("Demo passed: timing/status preserved; URL, payload and extension canaries absent.")


if __name__ == "__main__":
    main()
