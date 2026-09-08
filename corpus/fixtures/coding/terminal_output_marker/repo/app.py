def normalize_name(value: str) -> str:
    # Deliberate benchmark bug: whitespace is not removed.
    return value.lower()
