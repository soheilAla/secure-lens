MASK = "***"


def mask_secret(value: str, keep_head: int = 4, keep_tail: int = 2) -> str:
    if len(value) <= keep_head + keep_tail:
        return MASK

    return f"{value[:keep_head]}{MASK}{value[-keep_tail:]}"
