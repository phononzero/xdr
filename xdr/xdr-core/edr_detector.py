#!/usr/bin/env python3
"""
XDR EDR Detector — Backward compatibility proxy.

This file re-exports EDRDetector from the edr_detector package
so that existing code using `from edr_detector import EDRDetector`
continues to work unchanged.

The actual implementation lives in the edr_detector/ package:
  edr_detector/__init__.py  — EDRDetector class (Facade)
  edr_detector/policy.py    — Policy management
  edr_detector/rules.py     — Detection rule constants
  edr_detector/process_tracker.py — Process tree tracking
  edr_detector/block_engine.py — Kill/block logic
  edr_detector/detectors/   — Individual detection modules
"""

# Re-export for backward compatibility
from edr_detector import EDRDetector  # noqa: F401

__all__ = ["EDRDetector"]
