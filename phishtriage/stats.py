"""Small statistics for honest reporting on small samples."""
from __future__ import annotations

import math


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion. Unlike the plain "k/n ± error" formula it stays
    sensible at 0 or n successes: 0 false alarms out of 62 still means "up to about 6%"."""
    if total == 0:
        return 0.0, 1.0
    p = successes / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return max(0.0, centre - margin), min(1.0, centre + margin)


def count_with_range(successes: int, total: int) -> str:
    """'3 of 62 (4.8%, 95% range 1.7%-13.3%)'"""
    if total == 0:
        return "0 of 0"
    low, high = wilson(successes, total)
    return f"{successes} of {total} ({successes / total:.1%}, 95% range {low:.1%}-{high:.1%})"
