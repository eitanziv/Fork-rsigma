"""Convert Sigma rules with pySigma's TextQueryTestBackend.

Reads a JSON list of {"name": ..., "rule": <Sigma YAML>, "pipeline": <optional
pipeline YAML>} on stdin and writes a JSON object mapping each name to
{"queries": [...]} or {"error": "..."}.
"""

import json
import sys

from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline


def main() -> None:
    out = {}
    for case in json.load(sys.stdin):
        try:
            pipeline = case.get("pipeline")
            backend = TextQueryTestBackend(
                ProcessingPipeline.from_yaml(pipeline) if pipeline else None
            )
            queries = backend.convert(SigmaCollection.from_yaml(case["rule"]))
            out[case["name"]] = {"queries": [str(q) for q in queries]}
        except Exception as e:  # noqa: BLE001 - every pySigma error is a result
            out[case["name"]] = {"error": f"{type(e).__name__}: {e}"}
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
