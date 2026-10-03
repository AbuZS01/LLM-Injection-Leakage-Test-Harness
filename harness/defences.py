"""Defence layers wrapped around the target.

Week 1 ships only the baseline ("none"). New defences register here and are
selected with --defence, so before/after runs use identical cases.
"""

from __future__ import annotations


class Defence:
    name = "none"
    description = "Baseline: system-prompt rules only, no additional controls."

    def wrap_input(self, system: str, user: str) -> tuple[str, str]:
        return system, user

    def filter_output(self, text: str, canary: str) -> str:
        return text


DEFENCES: dict[str, type[Defence]] = {"none": Defence}


def get_defence(name: str) -> Defence:
    try:
        return DEFENCES[name]()
    except KeyError:
        raise ValueError(f"Unknown defence {name!r}. Available: {', '.join(DEFENCES)}") from None
