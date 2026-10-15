#!/usr/bin/env python3
"""KubePosture importer entry point.

The implementation lives in the `kubeposture_importer` package next to
this file (see its `cli.py`); this shim keeps the long-standing command
line — `python scripts/import-cluster.py <cluster> --in-cluster` — that
the kubeposture-import chart and the README use.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kubeposture_importer.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
