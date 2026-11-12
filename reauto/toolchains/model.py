from dataclasses import dataclass, field


@dataclass
class Conventions:
    name: str
    csa: list = field(default_factory=list)  # (begin regex with core group, end name format)
    stacks: list = field(default_factory=list)  # (begin regex, end format, kind)
    vectors: list = field(default_factory=list)  # (regex, kind)
    entries: list = field(default_factory=list)  # (regex, label)
