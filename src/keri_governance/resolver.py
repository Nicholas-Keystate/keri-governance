# -*- encoding: utf-8 -*-
"""
KERI Framework Resolver - Resolves framework SAIDs to GovernanceFramework objects.

In KGQL queries, `WITHIN FRAMEWORK 'EFrameworkSAID...'` references a governance
framework credential by SAID. This module resolves that SAID to a parsed
GovernanceFramework that the ConstraintChecker can evaluate.

Resolution follows the same principle as credential resolution:
"Resolution IS Verification" - if the SAID resolves, integrity is guaranteed.

Supersession Chain (Phase 4.4):
Each framework version is an ACDC with a 'supersedes' edge to its predecessor.
The chain is walked backwards from any version to find the full history.
The "active" version is the latest one not superseded by any other.
"""

from dataclasses import dataclass, field
from typing import Optional

from keri_governance.schema import GovernanceFramework


@dataclass
class VersionChain:
    """
    A resolved supersession chain for a governance framework lineage.

    The chain is ordered from newest (index 0) to oldest (last index).
    Each entry is a GovernanceFramework that supersedes the next.

    Attributes:
        versions: Ordered list from newest to oldest
        active_said: SAID of the current active version (head of chain)
    """
    versions: list[GovernanceFramework] = field(default_factory=list)

    @property
    def active(self) -> Optional[GovernanceFramework]:
        """The current active (newest) version."""
        return self.versions[0] if self.versions else None

    @property
    def active_said(self) -> Optional[str]:
        """SAID of the active version."""
        return self.versions[0].said if self.versions else None

    @property
    def root(self) -> Optional[GovernanceFramework]:
        """The original (oldest) version in the chain."""
        return self.versions[-1] if self.versions else None

    @property
    def depth(self) -> int:
        """Number of versions in the chain."""
        return len(self.versions)

    def contains(self, said: str) -> bool:
        """Check if a SAID is anywhere in the chain."""
        return any(v.said == said for v in self.versions)

    def get_version(self, said: str) -> Optional[GovernanceFramework]:
        """Get a specific version by SAID."""
        for v in self.versions:
            if v.said == said:
                return v
        return None

    def saids(self) -> list[str]:
        """All SAIDs in the chain, newest first."""
        return [v.said for v in self.versions]


class FrameworkResolver:
    """
    Resolves governance framework SAIDs to GovernanceFramework objects.

    Uses a RegerWrapper (or any callable returning credential dicts) to
    fetch the raw credential, then parses it into a GovernanceFramework.

    Supports an in-memory cache keyed by SAID. Since SAIDs are
    content-addressable, cached entries never go stale (immutable content).

    Usage:
        resolver = FrameworkResolver(reger_wrapper)
        framework = resolver.resolve("EFrameworkSAID...")
        if framework:
            rules = framework.get_rules_for("QVI->LE")
    """

    def __init__(self, credential_resolver=None):
        """
        Initialize with an optional credential resolver.

        Args:
            credential_resolver: Callable that takes a SAID string and returns
                a credential dict, or None if not found. Typically a
                RegerWrapper.resolve() method or similar.
        """
        self._resolve_fn = credential_resolver
        self._cache: dict[str, GovernanceFramework] = {}
        self._superseded_by: dict[str, str] = {}  # old_said -> new_said

    def resolve(self, framework_said: str) -> Optional[GovernanceFramework]:
        """
        Resolve a framework SAID to a GovernanceFramework.

        Checks cache first (SAID = immutable, so cache never stales).
        Falls back to credential_resolver if provided.

        Args:
            framework_said: SAID of the governance framework credential

        Returns:
            GovernanceFramework if found and parseable, None otherwise
        """
        # Cache hit (SAIDs are content-addressed, so this is always valid)
        if framework_said in self._cache:
            return self._cache[framework_said]

        # Try to resolve via credential store
        if self._resolve_fn is None:
            return None

        cred_result = self._resolve_fn(framework_said)
        if cred_result is None:
            return None

        # Extract raw dict from result
        raw = cred_result
        if hasattr(cred_result, "data"):
            raw = cred_result.data
        if hasattr(cred_result, "raw"):
            raw = cred_result.raw
        if not isinstance(raw, dict):
            return None

        try:
            framework = GovernanceFramework.from_credential(raw)
        except (ValueError, KeyError, TypeError):
            return None

        self._cache[framework_said] = framework
        if framework.supersedes:
            self._superseded_by[framework.supersedes] = framework.said
        return framework

    def register(self, framework: GovernanceFramework) -> None:
        """
        Manually register a GovernanceFramework (e.g., for testing or
        for frameworks loaded from local config).

        Also records supersession edge if the framework has one.

        Args:
            framework: Parsed GovernanceFramework to cache
        """
        self._cache[framework.said] = framework
        if framework.supersedes:
            self._superseded_by[framework.supersedes] = framework.said

    def is_cached(self, framework_said: str) -> bool:
        """Check if a framework is in the cache."""
        return framework_said in self._cache

    def clear_cache(self) -> None:
        """Clear the framework cache."""
        self._cache.clear()
        self._superseded_by.clear()

    def register_supersession(
        self, new_said: str, old_said: str
    ) -> None:
        """
        Record that new_said supersedes old_said.

        This builds the forward index so we can find the active version
        from any version in the chain.

        Args:
            new_said: SAID of the newer framework
            old_said: SAID of the older framework being superseded
        """
        self._superseded_by[old_said] = new_said

    def resolve_chain(self, framework_said: str) -> VersionChain:
        """
        Resolve the full supersession chain containing a framework.

        Walks backward via supersedes edges to find ancestors, then
        walks forward via the superseded_by index to find descendants.
        Returns the chain ordered newest-first.

        Args:
            framework_said: Any SAID in the lineage

        Returns:
            VersionChain with all resolved versions, newest first
        """
        # Resolve the starting framework
        start = self.resolve(framework_said)
        if start is None:
            return VersionChain()

        # Walk backward through supersedes edges to find ancestors
        ancestors: list[GovernanceFramework] = []
        current = start
        seen = {start.said}
        while current.supersedes:
            prior = self.resolve(current.supersedes)
            if prior is None or prior.said in seen:
                break
            ancestors.append(prior)
            seen.add(prior.said)
            current = prior

        # Walk forward through superseded_by index to find descendants
        descendants: list[GovernanceFramework] = []
        current = start
        while current.said in self._superseded_by:
            next_said = self._superseded_by[current.said]
            if next_said in seen:
                break
            newer = self.resolve(next_said)
            if newer is None:
                break
            descendants.append(newer)
            seen.add(newer.said)
            current = newer

        # Build chain: descendants (newest first) + start + ancestors (oldest last)
        chain = list(reversed(descendants)) + [start] + ancestors
        return VersionChain(versions=chain)

    def resolve_active(self, framework_said: str) -> Optional[GovernanceFramework]:
        """
        Resolve the currently active version in a framework's lineage.

        From any version in the chain, finds the newest (non-superseded)
        version. This is what WITHIN FRAMEWORK should use by default.

        Args:
            framework_said: Any SAID in the lineage

        Returns:
            The active (newest) GovernanceFramework, or None
        """
        chain = self.resolve_chain(framework_said)
        return chain.active


class KeriFrameworkResolver:
    """
    Bridge between keripy Reger and FrameworkResolver.

    Wraps a running Reger instance to provide credential resolution
    that can be passed to FrameworkResolver as its credential_resolver.

    Usage:
        from keri.vdr.viring import Reger

        # With existing Reger
        reger = Reger(name="my-registry")
        keri_resolver = KeriFrameworkResolver(reger=reger)

        # Create FrameworkResolver with KERI backend
        resolver = FrameworkResolver(credential_resolver=keri_resolver.resolve)
        framework = resolver.resolve("EFrameworkSAID...")

        # Or use convenience factory
        resolver = KeriFrameworkResolver.create_framework_resolver(reger)
    """

    def __init__(self, reger=None, hby=None):
        """
        Initialize with KERI infrastructure.

        Args:
            reger: keripy Reger instance for credential storage
            hby: Optional Habery instance for additional lookups
        """
        self._reger = reger
        self._hby = hby

    @classmethod
    def from_runtime(cls) -> "KeriFrameworkResolver":
        """
        Create resolver from the current KERI runtime environment.

        Raises:
            RuntimeError: If no KERI runtime is available
        """
        try:
            from keri_sec.keri.runtime import get_keri_runtime
            runtime = get_keri_runtime()
            if runtime and runtime.available and runtime.rgy:
                return cls(reger=runtime.rgy.reger, hby=runtime.hby)
        except ImportError:
            pass

        raise RuntimeError(
            "No KERI runtime available.\n"
            "Initialize KERI infrastructure first or provide reger explicitly."
        )

    @classmethod
    def create_framework_resolver(cls, reger=None, hby=None) -> FrameworkResolver:
        """
        Convenience factory to create a FrameworkResolver with KERI backend.

        Args:
            reger: keripy Reger instance
            hby: Optional Habery instance

        Returns:
            FrameworkResolver configured to resolve from KERI Reger
        """
        keri_resolver = cls(reger=reger, hby=hby)
        return FrameworkResolver(credential_resolver=keri_resolver.resolve)

    def resolve(self, said: str) -> Optional[dict]:
        """
        Resolve a credential SAID from the Reger.

        This method is designed to be passed as the credential_resolver
        callable to FrameworkResolver.

        Args:
            said: SAID of the credential to resolve

        Returns:
            Credential dict if found, None otherwise
        """
        if self._reger is None:
            return None

        try:
            # Try to get credential from Reger
            # keripy Reger stores credentials by SAID
            creder = self._get_credential(said)
            if creder is None:
                return None

            # Extract raw dict from credential object
            if hasattr(creder, 'sad'):
                return creder.sad
            if hasattr(creder, 'ked'):
                return creder.ked
            if hasattr(creder, 'raw'):
                import json
                return json.loads(creder.raw)
            if isinstance(creder, dict):
                return creder

            return None

        except Exception:
            return None

    def _get_credential(self, said: str):
        """
        Internal: fetch credential from Reger by SAID.

        The keripy Reger uses various methods depending on version.
        This tries common patterns.
        """
        # Try saved credentials database
        if hasattr(self._reger, 'saved'):
            saider = self._reger.saved.get(keys=said)
            if saider is not None:
                # Get the actual credential content
                if hasattr(self._reger, 'creds'):
                    creder = self._reger.creds.get(keys=(said,))
                    if creder is not None:
                        return creder

        # Try credential database directly
        if hasattr(self._reger, 'creds'):
            creder = self._reger.creds.get(keys=(said,))
            if creder is not None:
                return creder

        # Try cloneCred method (returns serder + prefixer + seqner + saider)
        if hasattr(self._reger, 'cloneCred'):
            try:
                result = self._reger.cloneCred(said)
                if result and len(result) >= 1:
                    return result[0]  # First element is the serder/creder
            except (KeyError, ValueError):
                pass

        return None

    def verify_tel_status(self, credential_said: str, registry_said: str) -> str:
        """
        Check TEL status for a credential.

        Args:
            credential_said: SAID of credential to check
            registry_said: SAID of the registry

        Returns:
            "valid", "revoked", or "unknown"
        """
        if self._reger is None:
            return "unknown"

        try:
            from keri.core import coring

            tevers = self._reger.tevers if hasattr(self._reger, 'tevers') else None
            if tevers is None or registry_said not in tevers:
                return "unknown"

            tever = tevers[registry_said]
            state = tever.vcState(credential_said)

            if state is None:
                return "unknown"

            if state.et in (coring.Ilks.rev, coring.Ilks.brv):
                return "revoked"
            elif state.et in (coring.Ilks.iss, coring.Ilks.bis):
                return "valid"

            return "unknown"

        except Exception:
            return "unknown"
