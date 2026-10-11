import re


ANSI_ESCAPE = re.compile(
    r"\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\)|P.*?\x1B\\|[@-_])",
    re.DOTALL,
)


def sanitize_terminal_text(value, max_length=120):
    """Remove terminal controls and bound untrusted text before display."""

    text = ANSI_ESCAPE.sub("", str(value))
    text = "".join(
        character if character.isprintable() else " "
        for character in text
    )
    text = " ".join(text.split())

    if len(text) > max_length:
        return text[:max_length - 3] + "..."

    return text
