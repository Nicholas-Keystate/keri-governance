# -*- encoding: utf-8 -*-
"""
Tests for Cardinal Rules Engine.

Tests artifact-type governance: ArtifactType, Operation, CardinalRule,
CardinalRuleSet, CardinalChecker, and default rules.
"""

import pytest

from keri_governance.cardinal import (
    ArtifactType,
    Operation,
    CardinalRule,
    CardinalRuleSet,
    CardinalChecker,
    CardinalCheckResult,
    default_cardinal_rules,
)
from keri_governance.primitives import StrengthLevel


# ── ArtifactType Tests ────────────────────────────────────────────────


class TestArtifactType:
    """ArtifactType enum values."""

    def test_five_types(self):
        assert len(ArtifactType) == 5

    def test_values(self):
        assert ArtifactType.ALG.value == "alg"
        assert ArtifactType.SCH.value == "sch"
        assert ArtifactType.PRO.value == "pro"
        assert ArtifactType.PKG.value == "pkg"
        assert ArtifactType.RUN.value == "run"

    def test_from_string(self):
        assert ArtifactType("alg") == ArtifactType.ALG
        assert ArtifactType("pkg") == ArtifactType.PKG

    def test_invalid_string(self):
        with pytest.raises(ValueError):
            ArtifactType("invalid")


class TestOperation:
    """Operation enum values."""

    def test_seven_operations(self):
        assert len(Operation) == 7

    def test_values(self):
        assert Operation.REGISTER.value == "register"
        assert Operation.ROTATE.value == "rotate"
        assert Operation.DEPRECATE.value == "deprecate"
        assert Operation.REVOKE.value == "revoke"
        assert Operation.VERIFY.value == "verify"
        assert Operation.RESOLVE.value == "resolve"
        assert Operation.EXECUTE.value == "execute"


# ── CardinalRule Tests ────────────────────────────────────────────────


class TestCardinalRule:
    """CardinalRule data model."""

    def test_construction(self):
        rule = CardinalRule(
            ArtifactType.ALG,
            Operation.REGISTER,
            StrengthLevel.TEL_ANCHORED,
            "Test rationale",
        )
        assert rule.artifact_type == ArtifactType.ALG
        assert rule.operation == Operation.REGISTER
        assert rule.min_strength == StrengthLevel.TEL_ANCHORED
        assert rule.rationale == "Test rationale"

    def test_frozen(self):
        rule = CardinalRule(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED)
        with pytest.raises(AttributeError):
            rule.min_strength = StrengthLevel.ANY

    def test_default_rationale(self):
        rule = CardinalRule(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED)
        assert rule.rationale == ""


# ── CardinalRuleSet Tests ─────────────────────────────────────────────


class TestCardinalRuleSet:
    """CardinalRuleSet collection."""

    def test_empty(self):
        rs = CardinalRuleSet()
        assert len(rs) == 0

    def test_add_and_get(self):
        rule = CardinalRule(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED)
        rs = CardinalRuleSet([rule])
        assert rs.get(ArtifactType.ALG, Operation.REGISTER) is rule

    def test_get_missing(self):
        rs = CardinalRuleSet()
        assert rs.get(ArtifactType.ALG, Operation.REGISTER) is None

    def test_contains(self):
        rule = CardinalRule(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED)
        rs = CardinalRuleSet([rule])
        assert (ArtifactType.ALG, Operation.REGISTER) in rs
        assert (ArtifactType.PKG, Operation.REGISTER) not in rs

    def test_rules_for_type(self):
        rules = [
            CardinalRule(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED),
            CardinalRule(ArtifactType.ALG, Operation.ROTATE, StrengthLevel.KEL_ANCHORED),
            CardinalRule(ArtifactType.PKG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED),
        ]
        rs = CardinalRuleSet(rules)
        alg_rules = rs.rules_for_type(ArtifactType.ALG)
        assert len(alg_rules) == 2
        pkg_rules = rs.rules_for_type(ArtifactType.PKG)
        assert len(pkg_rules) == 1

    def test_all_rules(self):
        rules = [
            CardinalRule(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED),
            CardinalRule(ArtifactType.PKG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED),
        ]
        rs = CardinalRuleSet(rules)
        assert len(rs.all_rules()) == 2

    def test_add_replaces(self):
        r1 = CardinalRule(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED)
        r2 = CardinalRule(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.SAID_ONLY)
        rs = CardinalRuleSet([r1])
        rs.add(r2)
        assert rs.get(ArtifactType.ALG, Operation.REGISTER).min_strength == StrengthLevel.SAID_ONLY
        assert len(rs) == 1


# ── CardinalChecker Tests ─────────────────────────────────────────────


class TestCardinalChecker:
    """CardinalChecker evaluation."""

    @pytest.fixture
    def checker(self):
        rules = [
            CardinalRule(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED),
            CardinalRule(ArtifactType.ALG, Operation.ROTATE, StrengthLevel.KEL_ANCHORED),
            CardinalRule(ArtifactType.ALG, Operation.VERIFY, StrengthLevel.SAID_ONLY),
            CardinalRule(ArtifactType.ALG, Operation.RESOLVE, StrengthLevel.ANY),
        ]
        return CardinalChecker(CardinalRuleSet(rules))

    def test_meets_exact_strength(self, checker):
        result = checker.check(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED)
        assert result.allowed is True

    def test_exceeds_strength(self, checker):
        result = checker.check(ArtifactType.ALG, Operation.ROTATE, StrengthLevel.TEL_ANCHORED)
        assert result.allowed is True

    def test_insufficient_strength(self, checker):
        result = checker.check(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.KEL_ANCHORED)
        assert result.allowed is False
        assert "requires" in result.message
        assert "TEL_ANCHORED" in result.message

    def test_any_satisfies_any(self, checker):
        result = checker.check(ArtifactType.ALG, Operation.RESOLVE, StrengthLevel.ANY)
        assert result.allowed is True

    def test_ungoverned_operation_allowed(self, checker):
        result = checker.check(ArtifactType.ALG, Operation.EXECUTE, StrengthLevel.ANY)
        assert result.allowed is True
        assert "No cardinal rule" in result.message

    def test_ungoverned_artifact_type(self, checker):
        result = checker.check(ArtifactType.PKG, Operation.REGISTER, StrengthLevel.ANY)
        assert result.allowed is True

    def test_result_has_rule(self, checker):
        result = checker.check(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED)
        assert result.rule is not None
        assert result.rule.artifact_type == ArtifactType.ALG

    def test_result_to_dict(self, checker):
        result = checker.check(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.KEL_ANCHORED)
        d = result.to_dict()
        assert d["allowed"] is False
        assert d["artifact_type"] == "alg"
        assert d["operation"] == "register"
        assert d["min_strength"] == "TEL_ANCHORED"
        assert d["actual_strength"] == "KEL_ANCHORED"

    def test_check_all(self, checker):
        results = checker.check_all(ArtifactType.ALG, StrengthLevel.KEL_ANCHORED)
        assert len(results) == 4
        # KEL_ANCHORED meets ROTATE (KEL_ANCHORED), VERIFY (SAID_ONLY), RESOLVE (ANY)
        assert results[Operation.ROTATE].allowed is True
        assert results[Operation.VERIFY].allowed is True
        assert results[Operation.RESOLVE].allowed is True
        # But not REGISTER (TEL_ANCHORED)
        assert results[Operation.REGISTER].allowed is False


# ── Strength Ladder Tests ─────────────────────────────────────────────


class TestStrengthLadder:
    """Verify the full strength ladder for each operation."""

    @pytest.fixture
    def checker(self):
        return CardinalChecker(default_cardinal_rules())

    @pytest.mark.parametrize("artifact_type", list(ArtifactType))
    def test_register_requires_tel(self, checker, artifact_type):
        """All artifact types require TEL_ANCHORED for registration."""
        result = checker.check(artifact_type, Operation.REGISTER, StrengthLevel.TEL_ANCHORED)
        assert result.allowed is True
        result = checker.check(artifact_type, Operation.REGISTER, StrengthLevel.KEL_ANCHORED)
        assert result.allowed is False

    @pytest.mark.parametrize("artifact_type", list(ArtifactType))
    def test_revoke_requires_tel(self, checker, artifact_type):
        """All artifact types require TEL_ANCHORED for revocation."""
        result = checker.check(artifact_type, Operation.REVOKE, StrengthLevel.TEL_ANCHORED)
        assert result.allowed is True
        result = checker.check(artifact_type, Operation.REVOKE, StrengthLevel.KEL_ANCHORED)
        assert result.allowed is False

    @pytest.mark.parametrize("artifact_type", list(ArtifactType))
    def test_resolve_allows_any(self, checker, artifact_type):
        """All artifact types allow ANY strength for resolution."""
        result = checker.check(artifact_type, Operation.RESOLVE, StrengthLevel.ANY)
        assert result.allowed is True

    @pytest.mark.parametrize("artifact_type", list(ArtifactType))
    def test_verify_requires_said(self, checker, artifact_type):
        """All artifact types require at least SAID_ONLY for verification."""
        result = checker.check(artifact_type, Operation.VERIFY, StrengthLevel.SAID_ONLY)
        assert result.allowed is True
        result = checker.check(artifact_type, Operation.VERIFY, StrengthLevel.ANY)
        assert result.allowed is False


# ── Default Rules Tests ───────────────────────────────────────────────


class TestDefaultCardinalRules:
    """Verify default_cardinal_rules() configuration."""

    def test_returns_ruleset(self):
        rs = default_cardinal_rules()
        assert isinstance(rs, CardinalRuleSet)

    def test_all_types_covered(self):
        rs = default_cardinal_rules()
        for at in ArtifactType:
            rules = rs.rules_for_type(at)
            assert len(rules) >= 5, f"Expected at least 5 rules for {at.value}"

    def test_total_rule_count(self):
        rs = default_cardinal_rules()
        # ALG: 7, SCH: 6, PRO: 6, PKG: 7, RUN: 7 = 33
        assert len(rs) == 33

    def test_all_rules_have_rationale(self):
        rs = default_cardinal_rules()
        for rule in rs.all_rules():
            assert len(rule.rationale) > 0, f"Missing rationale: {rule.artifact_type.value}:{rule.operation.value}"

    def test_schema_rotate_is_tel(self):
        """Schema rotation is TEL_ANCHORED (breaking changes affect credentials)."""
        rs = default_cardinal_rules()
        rule = rs.get(ArtifactType.SCH, Operation.ROTATE)
        assert rule.min_strength == StrengthLevel.TEL_ANCHORED

    def test_alg_rotate_is_kel(self):
        """Algorithm rotation is KEL_ANCHORED (not breaking like schemas)."""
        rs = default_cardinal_rules()
        rule = rs.get(ArtifactType.ALG, Operation.ROTATE)
        assert rule.min_strength == StrengthLevel.KEL_ANCHORED

    def test_pkg_execute_is_kel(self):
        """Package execution requires KEL_ANCHORED (publisher verification)."""
        rs = default_cardinal_rules()
        rule = rs.get(ArtifactType.PKG, Operation.EXECUTE)
        assert rule.min_strength == StrengthLevel.KEL_ANCHORED

    def test_pkg_rotate_is_tel(self):
        """Package version requires TEL_ANCHORED (supply chain integrity)."""
        rs = default_cardinal_rules()
        rule = rs.get(ArtifactType.PKG, Operation.ROTATE)
        assert rule.min_strength == StrengthLevel.TEL_ANCHORED


# ── Cross-Algebra Integration ─────────────────────────────────────────


class TestCardinalStrengthAlgebra:
    """Cardinal rules integrate correctly with StrengthLevel algebra."""

    def test_stronger_always_satisfies_weaker(self):
        """If checker allows level L, it allows all stronger levels."""
        checker = CardinalChecker(default_cardinal_rules())
        levels = sorted(StrengthLevel, key=lambda s: s.value)

        for at in ArtifactType:
            for op in Operation:
                for i, level in enumerate(levels):
                    result = checker.check(at, op, level)
                    if result.allowed:
                        # All stronger levels must also be allowed
                        for stronger in levels[i:]:
                            assert checker.check(at, op, stronger).allowed, (
                                f"{at.value}:{op.value}: {stronger.name} should satisfy "
                                f"if {level.name} does"
                            )

    def test_monotonicity(self):
        """For each governed rule, there's a clean cutoff in the strength ladder."""
        rs = default_cardinal_rules()
        levels = sorted(StrengthLevel, key=lambda s: s.value)
        checker = CardinalChecker(rs)

        for rule in rs.all_rules():
            found_cutoff = False
            for level in levels:
                result = checker.check(rule.artifact_type, rule.operation, level)
                if result.allowed and not found_cutoff:
                    found_cutoff = True
                    # From here, all stronger levels must pass
                elif found_cutoff:
                    assert result.allowed, (
                        f"Monotonicity violated: {rule.artifact_type.value}:{rule.operation.value} "
                        f"allowed at weaker but denied at {level.name}"
                    )
