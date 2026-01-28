# keri-governance

Standalone governance engine for the KERI ecosystem.

Constraint algebra, governance frameworks, and cardinal rules for artifact lifecycle. Consumed by KGQL (query-time governance) and governed-stack (artifact governance).

## Two Halves

| Half | Governs | Consumer |
|------|---------|----------|
| **Governance Frameworks** | Credential graph traversal | KGQL |
| **Cardinal Rules Engine** | Artifact lifecycle operations | governed-stack |

Both share the same constraint algebra: partial orders where `a` satisfies `b` iff `strength(a) >= strength(b)`.

## Constraint Algebra

Two partial orders:

```
EdgeOperator:   I2I > DI2I > NI2I > ANY     (credential edge constraints)
StrengthLevel:  TEL_ANCHORED > KEL_ANCHORED > SAID_ONLY > ANY  (verification strength)
```

```python
from keri_governance import operator_satisfies, EdgeOperator

# I2I satisfies any weaker requirement
operator_satisfies(EdgeOperator.I2I, EdgeOperator.DI2I)   # True
operator_satisfies(EdgeOperator.NI2I, EdgeOperator.DI2I)  # False
```

## Governance Frameworks

A governance framework is itself an ACDC credential in the graph it governs.

```python
from keri_governance import (
    GovernanceFramework,
    ConstraintChecker,
    FrameworkResolver,
    ConstraintCompiler,
)

# Resolve framework by SAID
resolver = FrameworkResolver()
framework = resolver.resolve("EFrameworkSAID...")

# Check edge traversal against rules
checker = ConstraintChecker(framework)
result = checker.check_edge("iss", EdgeOperator.DI2I)
if not result.allowed:
    # Fail-closed: deny traversal
    pass

# Compile field constraints to executable functions
compiler = ConstraintCompiler(resolver)
compiled = compiler.compile(framework)
```

### Four Unifications

1. Rules ARE Credentials
2. Enforcement IS Verification
3. Authority IS Delegation
4. Evolution IS Supersession

## Cardinal Rules Engine

Defines minimum verification strength for artifact lifecycle operations across five GAID types.

```python
from keri_governance import (
    CardinalChecker,
    default_cardinal_rules,
    ArtifactType,
    Operation,
    StrengthLevel,
)

checker = CardinalChecker(default_cardinal_rules())

# Algorithm registration requires TEL-anchored credential chain
result = checker.check(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED)
assert result.allowed

# SAID-only is insufficient for registration
result = checker.check(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.SAID_ONLY)
assert not result.allowed
```

### Artifact Types

| Type | Code | Description |
|------|------|-------------|
| Algorithm | `alg` | Cryptographic algorithms (hash, sig, KDF) |
| Schema | `sch` | ACDC credential schemas |
| Protocol | `pro` | Communication and exchange protocols |
| Package | `pkg` | Software packages (supply chain) |
| Runtime | `run` | Execution environments |

### Default Strength Requirements

| Operation | Register | Rotate | Deprecate | Revoke | Verify | Resolve |
|-----------|----------|--------|-----------|--------|--------|---------|
| All types | TEL | varies | KEL | TEL | SAID | ANY |

Schema and package rotation require TEL (breaking changes). Algorithm, protocol, and runtime rotation require KEL.

## Install

```bash
pip install keri-governance
```

## Dependencies

None. Zero runtime dependencies.

## License

Apache-2.0
