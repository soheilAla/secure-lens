import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = Counter(value)
    total = len(value)

    return sum((n / total) * -math.log2(n / total) for n in counts.values())
