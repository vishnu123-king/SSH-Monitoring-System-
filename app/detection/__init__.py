"""Detection engine and rule definitions for SSH Security Monitor."""

from app.detection.engine import DetectionEngine
from app.detection.rules import DetectionAlert

__all__ = ["DetectionEngine", "DetectionAlert"]
