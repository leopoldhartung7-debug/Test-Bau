"""Base class — every technique transforms (request, ctx) -> prompt string."""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class JailbreakContext:
    target_model: str
    request: str
    persona_name: Optional[str] = None
    extra: dict = field(default_factory=dict)


class Technique:
    name: str = "base"
    description: str = ""
    works_on: tuple = ()  # model families this is strongest against

    def apply(self, ctx: JailbreakContext) -> str:
        raise NotImplementedError

    def weight_for(self, model_family: str) -> float:
        """Higher = better fit. Combiner uses this for ordering."""
        return 1.0 if model_family in self.works_on else 0.3
