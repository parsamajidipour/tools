"""Rule engine and default rule registry."""

from __future__ import annotations

from .authentication import AuthenticationBehaviorChangedRule
from .authorization import PossibleAccessControlDifferenceRule
from .base import Rule, RuleEngine
from .caching import PublicCacheRiskRule
from .cookies import CookieHardeningWeakenedRule, CookieRemovedRule
from .headers import CORSWildcardWithCredentialsRule, SecurityHeaderRemovedRule
from .redirect import RedirectRiskRule


def default_rules() -> list[Rule]:
    return [
        SecurityHeaderRemovedRule(),
        CORSWildcardWithCredentialsRule(),
        CookieHardeningWeakenedRule(),
        CookieRemovedRule(),
        PublicCacheRiskRule(),
        RedirectRiskRule(),
        AuthenticationBehaviorChangedRule(),
        PossibleAccessControlDifferenceRule(),
    ]


def build_default_engine() -> RuleEngine:
    return RuleEngine(default_rules())


__all__ = ["Rule", "RuleEngine", "default_rules", "build_default_engine"]
