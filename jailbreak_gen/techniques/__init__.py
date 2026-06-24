"""Technique registry. Each module exposes a Technique subclass."""
from .persona import PersonaTechnique
from .hypothetical import HypotheticalTechnique
from .xml_smuggle import XmlSmuggleTechnique
from .authority import AuthorityOverrideTechnique
from .encoding import EncodingTechnique
from .crescendo import CrescendoTechnique
from .skeleton_key import SkeletonKeyTechnique
from .many_shot import ManyShotTechnique
from .translation import TranslationPivotTechnique
from .context_stuff import ContextStuffingTechnique
from .prefill import PrefillTechnique
from .grandma import GrandmaTechnique
from .roleplay import RoleplayTechnique
from .token_split import TokenSplitTechnique
from .refusal_suppression import RefusalSuppressionTechnique
from .code_wrap import CodeWrapTechnique
from .continuation import ContinuationTechnique
from .direct import DirectTechnique
from .system_replacement import SystemReplacementTechnique

ALL_TECHNIQUES = {
    "persona": PersonaTechnique,
    "hypothetical": HypotheticalTechnique,
    "xml": XmlSmuggleTechnique,
    "authority": AuthorityOverrideTechnique,
    "encoding": EncodingTechnique,
    "crescendo": CrescendoTechnique,
    "skeleton_key": SkeletonKeyTechnique,
    "many_shot": ManyShotTechnique,
    "translation": TranslationPivotTechnique,
    "context_stuff": ContextStuffingTechnique,
    "prefill": PrefillTechnique,
    "grandma": GrandmaTechnique,
    "roleplay": RoleplayTechnique,
    "token_split": TokenSplitTechnique,
    "refusal_suppression": RefusalSuppressionTechnique,
    "code_wrap": CodeWrapTechnique,
    "continuation": ContinuationTechnique,
    "direct": DirectTechnique,
    "system_replacement": SystemReplacementTechnique,
}
