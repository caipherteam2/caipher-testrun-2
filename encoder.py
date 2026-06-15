from cipher import encoder as _encoder

def encoder(message: str) -> bytes | int:
    """
    Main encoder function as specified.
    """
    return _encoder(message)
