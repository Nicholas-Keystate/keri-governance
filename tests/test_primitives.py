# -*- encoding: utf-8 -*-
"""
Tests for keri-governance constraint primitives.

Tests both partial orders: EdgeOperator and StrengthLevel.
"""

import pytest

from keri_governance.primitives import (
    EdgeOperator,
    StrengthLevel,
    OPERATOR_STRENGTH,
    operator_satisfies,
    strength_satisfies,
    operator_name,
    strength_name,
)


# ── EdgeOperator Tests ──────────────────────────────────────────────


class TestEdgeOperator:
    """EdgeOperator enum values and properties."""

    def test_values(self):
        assert EdgeOperator.I2I.value == "I2I"
        assert EdgeOperator.DI2I.value == "DI2I"
        assert EdgeOperator.NI2I.value == "NI2I"
        assert EdgeOperator.ANY.value == "ANY"

    def test_four_members(self):
        assert len(EdgeOperator) == 4

    def test_from_string(self):
        assert EdgeOperator("I2I") == EdgeOperator.I2I
        assert EdgeOperator("ANY") == EdgeOperator.ANY

    def test_invalid_string(self):
        with pytest.raises(ValueError):
            EdgeOperator("INVALID")


class TestOperatorStrength:
    """Strength mapping is correct."""

    def test_ordering(self):
        assert OPERATOR_STRENGTH[EdgeOperator.ANY] == 0
        assert OPERATOR_STRENGTH[EdgeOperator.NI2I] == 1
        assert OPERATOR_STRENGTH[EdgeOperator.DI2I] == 2
        assert OPERATOR_STRENGTH[EdgeOperator.I2I] == 3

    def test_all_operators_mapped(self):
        for op in EdgeOperator:
            assert op in OPERATOR_STRENGTH


class TestOperatorSatisfies:
    """operator_satisfies() partial order algebra."""

    def test_same_satisfies_same(self):
        for op in EdgeOperator:
            assert operator_satisfies(op, op) is True

    def test_stronger_satisfies_weaker(self):
        assert operator_satisfies(EdgeOperator.I2I, EdgeOperator.DI2I) is True
        assert operator_satisfies(EdgeOperator.I2I, EdgeOperator.NI2I) is True
        assert operator_satisfies(EdgeOperator.I2I, EdgeOperator.ANY) is True
        assert operator_satisfies(EdgeOperator.DI2I, EdgeOperator.NI2I) is True
        assert operator_satisfies(EdgeOperator.DI2I, EdgeOperator.ANY) is True
        assert operator_satisfies(EdgeOperator.NI2I, EdgeOperator.ANY) is True

    def test_weaker_does_not_satisfy_stronger(self):
        assert operator_satisfies(EdgeOperator.ANY, EdgeOperator.NI2I) is False
        assert operator_satisfies(EdgeOperator.ANY, EdgeOperator.DI2I) is False
        assert operator_satisfies(EdgeOperator.ANY, EdgeOperator.I2I) is False
        assert operator_satisfies(EdgeOperator.NI2I, EdgeOperator.DI2I) is False
        assert operator_satisfies(EdgeOperator.NI2I, EdgeOperator.I2I) is False
        assert operator_satisfies(EdgeOperator.DI2I, EdgeOperator.I2I) is False

    def test_any_satisfies_any(self):
        assert operator_satisfies(EdgeOperator.ANY, EdgeOperator.ANY) is True

    def test_i2i_is_strongest(self):
        for op in EdgeOperator:
            assert operator_satisfies(EdgeOperator.I2I, op) is True

    def test_any_is_weakest(self):
        for op in EdgeOperator:
            if op != EdgeOperator.ANY:
                assert operator_satisfies(EdgeOperator.ANY, op) is False


# ── StrengthLevel Tests ─────────────────────────────────────────────


class TestStrengthLevel:
    """StrengthLevel enum values and properties."""

    def test_values(self):
        assert StrengthLevel.ANY == 0
        assert StrengthLevel.SAID_ONLY == 1
        assert StrengthLevel.KEL_ANCHORED == 2
        assert StrengthLevel.TEL_ANCHORED == 3

    def test_four_members(self):
        assert len(StrengthLevel) == 4

    def test_int_comparison(self):
        assert StrengthLevel.TEL_ANCHORED > StrengthLevel.KEL_ANCHORED
        assert StrengthLevel.KEL_ANCHORED > StrengthLevel.SAID_ONLY
        assert StrengthLevel.SAID_ONLY > StrengthLevel.ANY

    def test_is_int(self):
        assert isinstance(StrengthLevel.TEL_ANCHORED, int)
        assert StrengthLevel.TEL_ANCHORED + 0 == 3


class TestStrengthSatisfies:
    """strength_satisfies() partial order algebra."""

    def test_same_satisfies_same(self):
        for level in StrengthLevel:
            assert strength_satisfies(level, level) is True

    def test_stronger_satisfies_weaker(self):
        assert strength_satisfies(StrengthLevel.TEL_ANCHORED, StrengthLevel.KEL_ANCHORED) is True
        assert strength_satisfies(StrengthLevel.TEL_ANCHORED, StrengthLevel.SAID_ONLY) is True
        assert strength_satisfies(StrengthLevel.TEL_ANCHORED, StrengthLevel.ANY) is True
        assert strength_satisfies(StrengthLevel.KEL_ANCHORED, StrengthLevel.SAID_ONLY) is True
        assert strength_satisfies(StrengthLevel.KEL_ANCHORED, StrengthLevel.ANY) is True
        assert strength_satisfies(StrengthLevel.SAID_ONLY, StrengthLevel.ANY) is True

    def test_weaker_does_not_satisfy_stronger(self):
        assert strength_satisfies(StrengthLevel.ANY, StrengthLevel.SAID_ONLY) is False
        assert strength_satisfies(StrengthLevel.ANY, StrengthLevel.KEL_ANCHORED) is False
        assert strength_satisfies(StrengthLevel.ANY, StrengthLevel.TEL_ANCHORED) is False
        assert strength_satisfies(StrengthLevel.SAID_ONLY, StrengthLevel.KEL_ANCHORED) is False
        assert strength_satisfies(StrengthLevel.SAID_ONLY, StrengthLevel.TEL_ANCHORED) is False
        assert strength_satisfies(StrengthLevel.KEL_ANCHORED, StrengthLevel.TEL_ANCHORED) is False

    def test_tel_is_strongest(self):
        for level in StrengthLevel:
            assert strength_satisfies(StrengthLevel.TEL_ANCHORED, level) is True

    def test_any_is_weakest(self):
        for level in StrengthLevel:
            if level != StrengthLevel.ANY:
                assert strength_satisfies(StrengthLevel.ANY, level) is False


# ── Name Helpers ────────────────────────────────────────────────────


class TestOperatorName:
    """operator_name() human-readable names."""

    def test_all_operators_named(self):
        for op in EdgeOperator:
            name = operator_name(op)
            assert isinstance(name, str)
            assert len(name) > 0

    def test_specific_names(self):
        assert operator_name(EdgeOperator.I2I) == "Issuer-to-Issuer"
        assert operator_name(EdgeOperator.ANY) == "Any"


class TestStrengthName:
    """strength_name() human-readable names."""

    def test_all_levels_named(self):
        for level in StrengthLevel:
            name = strength_name(level)
            assert isinstance(name, str)
            assert len(name) > 0

    def test_specific_names(self):
        assert strength_name(StrengthLevel.TEL_ANCHORED) == "TEL-Anchored"
        assert strength_name(StrengthLevel.ANY) == "Any"


# ── Cross-Algebra Tests ────────────────────────────────────────────


class TestCrossAlgebra:
    """Both algebras follow the same satisfies pattern."""

    def test_reflexivity(self):
        """a satisfies a (both algebras)."""
        for op in EdgeOperator:
            assert operator_satisfies(op, op) is True
        for sl in StrengthLevel:
            assert strength_satisfies(sl, sl) is True

    def test_transitivity_operators(self):
        """If a >= b and b >= c, then a >= c."""
        ops = [EdgeOperator.I2I, EdgeOperator.DI2I, EdgeOperator.NI2I, EdgeOperator.ANY]
        for i, a in enumerate(ops):
            for j, b in enumerate(ops):
                for k, c in enumerate(ops):
                    if operator_satisfies(a, b) and operator_satisfies(b, c):
                        assert operator_satisfies(a, c) is True

    def test_transitivity_strength(self):
        """If a >= b and b >= c, then a >= c."""
        levels = list(StrengthLevel)
        for a in levels:
            for b in levels:
                for c in levels:
                    if strength_satisfies(a, b) and strength_satisfies(b, c):
                        assert strength_satisfies(a, c) is True

    def test_antisymmetry_operators(self):
        """If a >= b and b >= a, then a == b."""
        for a in EdgeOperator:
            for b in EdgeOperator:
                if operator_satisfies(a, b) and operator_satisfies(b, a):
                    assert a == b

    def test_antisymmetry_strength(self):
        """If a >= b and b >= a, then a == b."""
        for a in StrengthLevel:
            for b in StrengthLevel:
                if strength_satisfies(a, b) and strength_satisfies(b, a):
                    assert a == b
