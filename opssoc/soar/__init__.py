"""SOAR writer: Cortex XSOAR and Google SecOps SOAR (ADR 002)."""

from opssoc.soar.base import Mode, SoarWriter, WriteResult
from opssoc.soar.secops import SecOpsSoarWriter
from opssoc.soar.xsoar import XsoarWriter

WRITERS: dict[str, type[SoarWriter]] = {"xsoar": XsoarWriter, "secops": SecOpsSoarWriter}

__all__ = ["WRITERS", "Mode", "SecOpsSoarWriter", "SoarWriter", "WriteResult", "XsoarWriter"]
