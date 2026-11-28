"""WAF payload mutator: layered encoding variants, equivalence dedupe, echo validation."""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import dataclass
from urllib.parse import quote, unquote


class WafError(ValueError):
    """Raised when a mutator operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Seed:
    seed_id: str
    payload: str
    case_sensitive: bool
    comments_active: bool


@dataclass(frozen=True)
class Variant:
    variant_id: str
    seed_id: str
    kind: str
    layer: int
    raw: str
    normalized: str


@dataclass(frozen=True)
class ValidationResult:
    variant_id: str
    state: str


_BLOCKED_STATUSES = frozenset({403, 406, 429})
_VALIDATION_STATES = frozenset(
    {"equivalent", "different", "blocked", "unverified"}
)
_STAT_KEYS = (
    "seeds",
    "variants",
    "deduped",
    "validated",
    "equivalent",
    "different",
    "blocked",
    "suppressed",
    "restores",
)
_TRANSFORMS = frozenset({"case_swap", "comment_pad", "space_to_plus"})
_URL_LAYER_RE = re.compile(r"^urlencode_l([1-9][0-9]*)$")


class WafPayloadMutator:
    """Generate encoded payload variants and converge on validated equivalents."""

    VERSION = 1

    def __init__(self, *, max_layers: int = 2, max_variants: int = 16) -> None:
        self.max_layers = self._nonnegative_int(max_layers, "max_layers")
        self.max_variants = self._nonnegative_int(max_variants, "max_variants")
        self._lock = threading.RLock()
        self._seeds: dict[str, Seed] = {}
        self._variants: dict[str, Variant] = {}
        self._validations: dict[str, ValidationResult] = {}
        self._stats = self._empty_stats()

    @staticmethod
    def _nonnegative_int(value: object, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
        return max(0, value)

    @staticmethod
    def _empty_stats() -> dict[str, int]:
        return {key: 0 for key in _STAT_KEYS}

    @staticmethod
    def _require_seed_id(seed_id: object) -> str:
        if not isinstance(seed_id, str) or seed_id == "":
            raise WafError("WAF_DUPLICATE_SEED", seed_id)
        return seed_id

    def _require_seed(self, seed_id: object) -> Seed:
        if not isinstance(seed_id, str):
            raise WafError("WAF_UNKNOWN_SEED", seed_id)
        seed = self._seeds.get(seed_id)
        if seed is None:
            raise WafError("WAF_UNKNOWN_SEED", seed_id)
        return seed

    @staticmethod
    def _validate_payload(payload: object) -> str:
        if not isinstance(payload, str) or payload == "":
            raise WafError("WAF_INVALID_SEED", payload)
        return payload

    def add_seed(self, seed_id: str, payload: str, *,
                 case_sensitive: bool = True,
                 comments_active: bool = True) -> Seed:
        with self._lock:
            seed_id = self._require_seed_id(seed_id)
            if seed_id in self._seeds:
                raise WafError("WAF_DUPLICATE_SEED", seed_id)
            payload = self._validate_payload(payload)
            seed = Seed(
                seed_id=seed_id,
                payload=payload,
                case_sensitive=bool(case_sensitive),
                comments_active=bool(comments_active),
            )
            self._seeds[seed_id] = seed
            self._stats["seeds"] += 1
            return seed

    def remove_seed(self, seed_id: str) -> bool:
        with self._lock:
            if not isinstance(seed_id, str) or seed_id not in self._seeds:
                return False
            variant_ids = [
                variant_id
                for variant_id, variant in self._variants.items()
                if variant.seed_id == seed_id
            ]
            for variant_id in variant_ids:
                self._discard_validation(variant_id)
                del self._variants[variant_id]
            del self._seeds[seed_id]
            self._stats["seeds"] -= 1
            return True

    @staticmethod
    def _encode_once(payload: str) -> str:
        return quote(payload, safe="")

    @staticmethod
    def _apply_transform(payload: str, kind: str) -> str:
        if kind == "case_swap":
            return payload.swapcase()
        if kind == "comment_pad":
            return payload.replace(" ", "/**/")
        if kind == "space_to_plus":
            return payload.replace(" ", "+")
        raise WafError("WAF_INVALID_KIND", kind)

    def _variant(
        self,
        seed: Seed,
        variant_id: str,
        kind: str,
        layer: int,
        raw: str,
    ) -> Variant:
        return Variant(
            variant_id=variant_id,
            seed_id=seed.seed_id,
            kind=kind,
            layer=layer,
            raw=raw,
            normalized=self.normalize(
                raw,
                case_sensitive=seed.case_sensitive,
                comments_active=seed.comments_active,
            ),
        )

    def mutate(self, seed_id: str) -> tuple[Variant, ...]:
        with self._lock:
            seed = self._require_seed(seed_id)
            potential = self.max_layers + 3
            emitted_count = min(potential, self.max_variants)
            produced: list[Variant] = []
            raw = seed.payload

            url_count = min(self.max_layers, emitted_count)
            for layer in range(1, url_count + 1):
                variant_id = f"{seed.seed_id}@urlencode_l{layer}"
                raw = self._encode_once(raw)
                candidate = self._variant(
                    seed, variant_id, f"urlencode_l{layer}", layer, raw
                )
                self._variants[variant_id] = candidate
                self._stats["variants"] += 1
                produced.append(candidate)

            transform_kinds = ("case_swap", "comment_pad", "space_to_plus")
            for kind in transform_kinds:
                if len(produced) >= emitted_count:
                    break
                variant_id = f"{seed.seed_id}@{kind}"
                transformed = self._apply_transform(seed.payload, kind)
                candidate = self._variant(seed, variant_id, kind, 0, transformed)
                self._variants[variant_id] = candidate
                self._stats["variants"] += 1
                produced.append(candidate)

            self._stats["suppressed"] += potential - emitted_count
            return tuple(produced)

    @staticmethod
    def _url_layers_for_kind(kind: str) -> int | None:
        match = _URL_LAYER_RE.match(kind)
        if match is not None:
            return int(match.group(1))
        return None

    def combine(self, seed_id: str, *kinds: str) -> Variant:
        with self._lock:
            seed = self._require_seed(seed_id)
            url_layers = 0
            for kind in kinds:
                if not isinstance(kind, str):
                    raise WafError("WAF_INVALID_KIND", kind)
                layers = self._url_layers_for_kind(kind)
                if layers is not None:
                    url_layers += layers
                    continue
                if kind not in _TRANSFORMS:
                    raise WafError("WAF_INVALID_KIND", kind)
            if url_layers > self.max_layers:
                raise WafError("WAF_INVALID_KIND", {"layer_cap": self.max_layers})

            raw = seed.payload
            for kind in kinds:
                layers = self._url_layers_for_kind(kind)
                if layers is not None:
                    for _ in range(layers):
                        raw = self._encode_once(raw)
                else:
                    raw = self._apply_transform(raw, kind)

            kind_name = "combo:" + "+".join(kinds)
            variant_id = f"{seed.seed_id}@{kind_name}"
            existing = self._variants.get(variant_id)
            if existing is not None:
                return existing
            candidate = self._variant(seed, variant_id, kind_name, url_layers, raw)
            self._variants[variant_id] = candidate
            self._stats["variants"] += 1
            return candidate

    def dedupe(self, variants) -> tuple[Variant, ...]:
        with self._lock:
            values = list(variants)
            prepared: list[tuple[Variant, str]] = []
            for value in values:
                if not isinstance(value, Variant):
                    raise WafError("WAF_INVALID_VARIANT", value)
                seed = self._require_seed(value.seed_id)
                key = self.normalize(
                    value.raw,
                    case_sensitive=seed.case_sensitive,
                    comments_active=seed.comments_active,
                )
                prepared.append((value, key))

            seen: set[str] = set()
            unique: list[Variant] = []
            for value, key in prepared:
                if key in seen:
                    continue
                seen.add(key)
                unique.append(value)
            self._stats["deduped"] += len(values) - len(unique)
            return tuple(unique)

    def normalize(self, payload: str, *, case_sensitive: bool = True,
                  comments_active: bool = True) -> str:
        if not isinstance(payload, str):
            raise WafError("WAF_INVALID_SEED", payload)
        decoded = payload
        while True:
            next_value = unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        if comments_active:
            decoded = decoded.replace("/**/", " ")
        decoded = " ".join(decoded.split())
        if not case_sensitive:
            decoded = decoded.lower()
        return decoded

    def validate_echo(self, variant_id: str, *, status_code: int,
                      echo: str | None = None) -> ValidationResult:
        with self._lock:
            variant = self._variants.get(variant_id)
            if variant is None:
                raise WafError("WAF_UNKNOWN_VARIANT", variant_id)

            if status_code is None:
                state = "unverified"
            elif isinstance(status_code, bool) or not isinstance(status_code, int):
                raise WafError("WAF_INVALID_STATUS", status_code)
            elif status_code <= 0:
                state = "unverified"
            elif 200 <= status_code < 300:
                seed = self._require_seed(variant.seed_id)
                expected = self.normalize(
                    seed.payload,
                    case_sensitive=seed.case_sensitive,
                    comments_active=seed.comments_active,
                )
                observed = (
                    self.normalize(
                        echo,
                        case_sensitive=seed.case_sensitive,
                        comments_active=seed.comments_active,
                    )
                    if isinstance(echo, str)
                    else None
                )
                state = "equivalent" if observed == expected else "different"
            elif status_code in _BLOCKED_STATUSES:
                state = "blocked"
            else:
                state = "unverified"

            self._record_validation(variant_id, state)
            return self._validations[variant_id]

    def _record_validation(self, variant_id: str, state: str) -> None:
        previous = self._validations.get(variant_id)
        if previous is None:
            self._stats["validated"] += 1
        elif previous.state != "unverified":
            self._stats[previous.state] -= 1
        self._validations[variant_id] = ValidationResult(variant_id, state)
        if state != "unverified":
            self._stats[state] += 1

    def _discard_validation(self, variant_id: str) -> None:
        previous = self._validations.pop(variant_id, None)
        if previous is None:
            return
        self._stats["validated"] -= 1
        if previous.state != "unverified":
            self._stats[previous.state] -= 1

    def rank(self, seed_id: str) -> tuple[Variant, ...]:
        with self._lock:
            self._require_seed(seed_id)
            tiers = {
                "equivalent": 0,
                "unverified": 1,
                "different": 2,
                "blocked": 3,
            }

            def sort_key(variant: Variant) -> tuple[int, int, str]:
                validation = self._validations.get(variant.variant_id)
                state = validation.state if validation is not None else "unverified"
                return (tiers[state], variant.layer, variant.variant_id)

            variants = (
                variant
                for variant in self._variants.values()
                if variant.seed_id == seed_id
            )
            return tuple(sorted(variants, key=sort_key))

    def survivors(self, seed_id: str) -> tuple[str, ...]:
        with self._lock:
            self._require_seed(seed_id)
            return tuple(sorted(
                variant_id
                for variant_id, validation in self._validations.items()
                if validation.state == "equivalent"
                and variant_id in self._variants
                and self._variants[variant_id].seed_id == seed_id
            ))

    def variant(self, variant_id: str) -> Variant | None:
        with self._lock:
            return self._variants.get(variant_id)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": self.VERSION,
                "seeds": copy.deepcopy(dict(self._seeds)),
                "variants": copy.deepcopy(dict(self._variants)),
                "validations": copy.deepcopy(dict(self._validations)),
                "stats": copy.deepcopy(dict(self._stats)),
            }

    @staticmethod
    def _coerce_seed(item: object) -> Seed:
        if isinstance(item, Seed):
            seed = Seed(
                seed_id=item.seed_id,
                payload=item.payload,
                case_sensitive=item.case_sensitive,
                comments_active=item.comments_active,
            )
        elif isinstance(item, dict):
            if set(item) != {
                "seed_id", "payload", "case_sensitive", "comments_active"
            }:
                raise WafError("WAF_SNAPSHOT_INVALID", item)
            seed = Seed(
                seed_id=item["seed_id"],
                payload=item["payload"],
                case_sensitive=item["case_sensitive"],
                comments_active=item["comments_active"],
            )
        else:
            raise WafError("WAF_SNAPSHOT_INVALID", item)

        if not isinstance(seed.seed_id, str) or seed.seed_id == "":
            raise WafError("WAF_SNAPSHOT_INVALID", item)
        if not isinstance(seed.payload, str) or seed.payload == "":
            raise WafError("WAF_SNAPSHOT_INVALID", item)
        if not isinstance(seed.case_sensitive, bool):
            raise WafError("WAF_SNAPSHOT_INVALID", item)
        if not isinstance(seed.comments_active, bool):
            raise WafError("WAF_SNAPSHOT_INVALID", item)
        return seed

    @staticmethod
    def _coerce_variant(item: object) -> Variant:
        if isinstance(item, Variant):
            variant = Variant(
                variant_id=item.variant_id,
                seed_id=item.seed_id,
                kind=item.kind,
                layer=item.layer,
                raw=item.raw,
                normalized=item.normalized,
            )
        elif isinstance(item, dict):
            if set(item) != {
                "variant_id", "seed_id", "kind", "layer", "raw", "normalized"
            }:
                raise WafError("WAF_SNAPSHOT_INVALID", item)
            variant = Variant(
                variant_id=item["variant_id"],
                seed_id=item["seed_id"],
                kind=item["kind"],
                layer=item["layer"],
                raw=item["raw"],
                normalized=item["normalized"],
            )
        else:
            raise WafError("WAF_SNAPSHOT_INVALID", item)

        if not isinstance(variant.variant_id, str) or variant.variant_id == "":
            raise WafError("WAF_SNAPSHOT_INVALID", item)
        if not isinstance(variant.seed_id, str):
            raise WafError("WAF_SNAPSHOT_INVALID", item)
        if not isinstance(variant.kind, str) or variant.kind == "":
            raise WafError("WAF_SNAPSHOT_INVALID", item)
        if (
            isinstance(variant.layer, bool)
            or not isinstance(variant.layer, int)
            or variant.layer < 0
        ):
            raise WafError("WAF_SNAPSHOT_INVALID", item)
        if not isinstance(variant.raw, str):
            raise WafError("WAF_SNAPSHOT_INVALID", item)
        if not isinstance(variant.normalized, str):
            raise WafError("WAF_SNAPSHOT_INVALID", item)
        return variant

    @staticmethod
    def _coerce_validation(item: object) -> ValidationResult:
        if isinstance(item, ValidationResult):
            result = ValidationResult(
                variant_id=item.variant_id,
                state=item.state,
            )
        elif isinstance(item, dict):
            if set(item) != {"variant_id", "state"}:
                raise WafError("WAF_SNAPSHOT_INVALID", item)
            result = ValidationResult(
                variant_id=item["variant_id"],
                state=item["state"],
            )
        else:
            raise WafError("WAF_SNAPSHOT_INVALID", item)

        if not isinstance(result.variant_id, str) or result.variant_id == "":
            raise WafError("WAF_SNAPSHOT_INVALID", item)
        if result.state not in _VALIDATION_STATES:
            raise WafError("WAF_SNAPSHOT_INVALID", item)
        return result

    @staticmethod
    def _coerce_stats(item: object) -> dict[str, int]:
        if not isinstance(item, dict) or set(item) != set(_STAT_KEYS):
            raise WafError("WAF_SNAPSHOT_INVALID", item)
        stats: dict[str, int] = {}
        for key in _STAT_KEYS:
            value = item[key]
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
            ):
                raise WafError("WAF_SNAPSHOT_INVALID", item)
            stats[key] = value
        return stats

    def restore(self, state: dict) -> None:
        with self._lock:
            if not isinstance(state, dict):
                raise WafError("WAF_SNAPSHOT_INVALID", state)
            if set(state) != {
                "version", "seeds", "variants", "validations", "stats"
            }:
                raise WafError("WAF_SNAPSHOT_INVALID", state)
            version = state["version"]
            if (
                isinstance(version, bool)
                or not isinstance(version, int)
                or version != self.VERSION
            ):
                raise WafError("WAF_SNAPSHOT_INVALID", state)
            for key in ("seeds", "variants", "validations"):
                if not isinstance(state[key], dict):
                    raise WafError("WAF_SNAPSHOT_INVALID", state)

            seeds: dict[str, Seed] = {}
            for key, item in state["seeds"].items():
                seed = self._coerce_seed(item)
                if key != seed.seed_id:
                    raise WafError("WAF_SNAPSHOT_INVALID", state)
                if seed.seed_id in seeds:
                    raise WafError("WAF_SNAPSHOT_INVALID", state)
                seeds[seed.seed_id] = seed

            variants: dict[str, Variant] = {}
            for key, item in state["variants"].items():
                variant = self._coerce_variant(item)
                if key != variant.variant_id:
                    raise WafError("WAF_SNAPSHOT_INVALID", state)
                if variant.variant_id in variants:
                    raise WafError("WAF_SNAPSHOT_INVALID", state)
                if variant.seed_id not in seeds:
                    raise WafError("WAF_SNAPSHOT_INVALID", state)
                variants[variant.variant_id] = variant

            validations: dict[str, ValidationResult] = {}
            for key, item in state["validations"].items():
                result = self._coerce_validation(item)
                if key != result.variant_id:
                    raise WafError("WAF_SNAPSHOT_INVALID", state)
                if result.variant_id in validations:
                    raise WafError("WAF_SNAPSHOT_INVALID", state)
                if result.variant_id not in variants:
                    raise WafError("WAF_SNAPSHOT_INVALID", state)
                validations[result.variant_id] = result

            stats = self._coerce_stats(state["stats"])

            self._seeds = copy.deepcopy(seeds)
            self._variants = copy.deepcopy(variants)
            self._validations = copy.deepcopy(validations)
            self._stats = copy.deepcopy(stats)
            self._stats["restores"] += 1

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(dict(self._stats))

    def reset(self) -> None:
        with self._lock:
            self._seeds.clear()
            self._variants.clear()
            self._validations.clear()
            self._stats = self._empty_stats()
