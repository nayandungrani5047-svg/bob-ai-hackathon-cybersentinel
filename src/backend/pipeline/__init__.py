"""
D2 Threat Intelligence — Processing Pipeline
=============================================

Public surface of the pipeline package.  Import the six main functions from
here rather than from the individual modules.

Usage::

    from backend.pipeline import (
        normalise,
        classify_fps,
        correlate,
        prioritise,
        map_techniques,
        generate_bluf,
    )
"""

from .normaliser import normalise
from .fp_classifier import classify_fps
from .correlator import correlate
from .prioritiser import prioritise
from .mitre_mapper import map_techniques
from .bluf_generator import generate_bluf

__all__ = [
    "normalise",
    "classify_fps",
    "correlate",
    "prioritise",
    "map_techniques",
    "generate_bluf",
]
