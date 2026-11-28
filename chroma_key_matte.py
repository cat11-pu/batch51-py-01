"""Chroma key matte: chroma distance matte, spill suppression and temporal blend."""

from __future__ import annotations

import math
import threading


_SNAPSHOT_VERSION = 1
_STAT_KEYS = ("frames", "keyed", "partial", "opaque", "spill", "stabilized")


class ChromaKeyError(ValueError):
    """Raised when a matte operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _validate_color(color) -> tuple[int, int, int]:
    try:
        if len(color) != 3:
            raise ChromaKeyError(
                "CHROMA_KEY_INVALID_COLOR",
                {"reason": "expected_rgb_triple", "value": color},
            )
        channels = tuple(color)
    except TypeError as exc:
        raise ChromaKeyError(
            "CHROMA_KEY_INVALID_COLOR",
            {"reason": "expected_rgb_triple", "value": color},
        ) from exc

    if any(not _is_int(channel) or not 0 <= channel <= 255 for channel in channels):
        raise ChromaKeyError(
            "CHROMA_KEY_INVALID_COLOR",
            {"reason": "channels_must_be_bytes", "value": color},
        )
    return channels[0], channels[1], channels[2]


def _validate_thresholds(similarity, softness) -> tuple[int, int]:
    if (
        not _is_int(similarity)
        or not _is_int(softness)
        or similarity < 0
        or softness < 0
        or similarity + softness > 510
    ):
        raise ChromaKeyError(
            "CHROMA_KEY_INVALID_THRESHOLD",
            {"similarity": similarity, "softness": softness},
        )
    return similarity, softness


def _validate_radius(radius) -> int:
    if not _is_int(radius) or not 0 <= radius <= 64:
        raise ChromaKeyError("CHROMA_KEY_INVALID_RADIUS", {"radius": radius})
    return radius


def _validate_motion(motion) -> float:
    if not _is_number(motion) or motion < 0:
        raise ChromaKeyError("CHROMA_KEY_INVALID_MOTION", {"motion": motion})
    return float(motion)


class ChromaKeyMatte:
    """Build per pixel coverage from a key colour and keep a short alpha history."""

    def __init__(self, *, width: int, height: int, key_color=(0, 255, 0),
                 similarity: int = 60, softness: int = 40,
                 feather_radius: int = 1, history_limit: int = 4,
                 shadow_luma: int = 48, shadow_keep: float = 0.6,
                 history_weight: float = 0.5,
                 motion_penalty: float = 0.25) -> None:
        if not _is_int(width) or width <= 0 or not _is_int(height) or height <= 0:
            raise ChromaKeyError(
                "CHROMA_KEY_BAD_FRAME", {"width": width, "height": height}
            )
        if not _is_int(history_limit) or history_limit < 0:
            raise ChromaKeyError(
                "CHROMA_KEY_INVALID_CONFIG", {"history_limit": history_limit}
            )
        if not _is_number(shadow_luma) or shadow_luma < 0:
            raise ChromaKeyError(
                "CHROMA_KEY_INVALID_CONFIG", {"shadow_luma": shadow_luma}
            )
        if not _is_number(shadow_keep) or not 0 <= shadow_keep <= 1:
            raise ChromaKeyError(
                "CHROMA_KEY_INVALID_CONFIG", {"shadow_keep": shadow_keep}
            )
        if not _is_number(history_weight) or not 0 <= history_weight <= 1:
            raise ChromaKeyError(
                "CHROMA_KEY_INVALID_CONFIG", {"history_weight": history_weight}
            )
        if not _is_number(motion_penalty) or motion_penalty < 0:
            raise ChromaKeyError(
                "CHROMA_KEY_INVALID_CONFIG", {"motion_penalty": motion_penalty}
            )

        self.width = width
        self.height = height
        self.similarity, self.softness = _validate_thresholds(similarity, softness)
        self.feather_radius = _validate_radius(feather_radius)
        self.history_limit = history_limit
        self.shadow_luma = float(shadow_luma)
        self.shadow_keep = float(shadow_keep)
        self.history_weight = float(history_weight)
        self.motion_penalty = float(motion_penalty)
        self._key_color = _validate_color(key_color)
        self._lock = threading.RLock()
        self._history: list[list[list[float]]] = []
        self._stats = {name: 0 for name in _STAT_KEYS}

    def _validate_frame(self, frame) -> None:
        try:
            if len(frame) != self.height:
                raise ChromaKeyError(
                    "CHROMA_KEY_BAD_FRAME",
                    {"reason": "row_count", "expected": self.height},
                )
            for row in frame:
                if len(row) != self.width:
                    raise ChromaKeyError(
                        "CHROMA_KEY_BAD_FRAME",
                        {"reason": "column_count", "expected": self.width},
                    )
                for pixel in row:
                    if len(pixel) != 3:
                        raise ChromaKeyError(
                            "CHROMA_KEY_BAD_FRAME",
                            {"reason": "pixel_shape", "value": pixel},
                        )
                    if any(
                        not _is_int(channel) or not 0 <= channel <= 255
                        for channel in pixel
                    ):
                        raise ChromaKeyError(
                            "CHROMA_KEY_BAD_FRAME",
                            {"reason": "pixel_channel", "value": pixel},
                        )
        except TypeError as exc:
            raise ChromaKeyError(
                "CHROMA_KEY_BAD_FRAME", {"reason": "expected_frame_matrix"}
            ) from exc

    def _validate_alpha(self, alpha, *, code: str) -> None:
        try:
            if len(alpha) != self.height:
                raise ChromaKeyError(
                    code, {"reason": "row_count", "expected": self.height}
                )
            for row in alpha:
                if len(row) != self.width:
                    raise ChromaKeyError(
                        code, {"reason": "column_count", "expected": self.width}
                    )
                for value in row:
                    if not _is_number(value) or not 0 <= value <= 1:
                        raise ChromaKeyError(
                            code, {"reason": "alpha_value", "value": value}
                        )
        except TypeError as exc:
            raise ChromaKeyError(
                code, {"reason": "expected_alpha_matrix"}
            ) from exc

    def _remember(self, alpha: list[list[float]]) -> None:
        if self.history_limit == 0:
            return
        self._history.append([row[:] for row in alpha])
        overflow = len(self._history) - self.history_limit
        if overflow > 0:
            del self._history[:overflow]

    def _compute_alpha(self, frame) -> list[list[float]]:
        key_r, key_g, key_b = self._key_color
        key_bg = key_b - key_g
        key_rg = key_r - key_g
        key_luma = 0.299 * key_r + 0.587 * key_g + 0.114 * key_b
        similarity = self.similarity
        softness = self.softness
        upper = similarity + softness
        shadow_luma = self.shadow_luma
        shadow_keep = self.shadow_keep

        result: list[list[float]] = []
        for row in frame:
            out_row: list[float] = []
            for red, green, blue in row:
                distance = max(
                    abs((blue - green) - key_bg),
                    abs((red - green) - key_rg),
                )
                if distance <= similarity:
                    value = 0.0
                elif softness == 0 or distance >= upper:
                    value = 1.0
                else:
                    value = (distance - similarity) / softness

                if distance <= similarity and shadow_luma > 0:
                    luma = 0.299 * red + 0.587 * green + 0.114 * blue
                    if luma < shadow_luma and luma < key_luma:
                        lift = shadow_keep * (
                            (shadow_luma - luma) / shadow_luma
                        )
                        if lift > value:
                            value = min(1.0, lift)

                if value <= 0.0:
                    value = 0.0
                elif value >= 1.0:
                    value = 1.0
                out_row.append(value)
            result.append(out_row)
        return result

    def set_key_color(self, color) -> tuple:
        normalized = _validate_color(color)
        with self._lock:
            self._key_color = normalized
            self._history.clear()
        return normalized

    def set_thresholds(self, *, similarity=None, softness=None) -> None:
        with self._lock:
            next_similarity = self.similarity if similarity is None else similarity
            next_softness = self.softness if softness is None else softness
            self.similarity, self.softness = _validate_thresholds(
                next_similarity, next_softness
            )

    def matte(self, frame) -> list:
        with self._lock:
            self._validate_frame(frame)
            alpha = self._compute_alpha(frame)
            self._remember(alpha)
            self._stats["frames"] += 1
            for row in alpha:
                for value in row:
                    if value == 0.0:
                        self._stats["keyed"] += 1
                    elif value == 1.0:
                        self._stats["opaque"] += 1
                    else:
                        self._stats["partial"] += 1
        return alpha

    def despill(self, frame, *, strength: float = 1.0) -> list:
        if not _is_number(strength) or not 0 <= strength <= 1:
            raise ChromaKeyError(
                "CHROMA_KEY_INVALID_STRENGTH", {"strength": strength}
            )

        with self._lock:
            self._validate_frame(frame)
            main = max(range(3), key=lambda index: self._key_color[index])
            others = [index for index in range(3) if index != main]
            affected = 0
            result: list[list[tuple]] = []

            for row in frame:
                out_row = []
                for pixel in row:
                    channels = list(pixel)
                    target = max(channels[others[0]], channels[others[1]])
                    if strength > 0 and channels[main] > target:
                        reduced = channels[main] + strength * (
                            target - channels[main]
                        )
                        channels[main] = int(round(reduced))
                        affected += 1
                    out_row.append(tuple(channels))
                result.append(out_row)

            self._stats["spill"] += affected
        return result

    def feather(self, alpha, radius=None) -> list:
        with self._lock:
            radius = self.feather_radius if radius is None else radius
            radius = _validate_radius(radius)
            self._validate_alpha(alpha, code="CHROMA_KEY_BAD_FRAME")
            if radius == 0:
                return [list(row) for row in alpha]

            horizontal: list[list[float]] = []
            for row in alpha:
                prefix = [0.0]
                running = 0.0
                for value in row:
                    running += float(value)
                    prefix.append(running)
                filtered_row = []
                for x in range(self.width):
                    left = max(0, x - radius)
                    right = min(self.width, x + radius + 1)
                    filtered_row.append(
                        (prefix[right] - prefix[left]) / (right - left)
                    )
                horizontal.append(filtered_row)

            result: list[list[float]] = [
                [0.0] * self.width for _ in range(self.height)
            ]
            for x in range(self.width):
                prefix = [0.0]
                running = 0.0
                for y in range(self.height):
                    running += horizontal[y][x]
                    prefix.append(running)
                for y in range(self.height):
                    top = max(0, y - radius)
                    bottom = min(self.height, y + radius + 1)
                    value = (prefix[bottom] - prefix[top]) / (bottom - top)
                    result[y][x] = min(1.0, max(0.0, value))
            return result

    def temporal_stabilize(self, alpha, *, motion: float = 0.0) -> list:
        motion = _validate_motion(motion)
        with self._lock:
            self._validate_alpha(alpha, code="CHROMA_KEY_BAD_FRAME")
            current = [[float(value) for value in row] for row in alpha]
            if not self._history:
                self._remember(current)
                return current

            weight = max(
                0.0, self.history_weight - motion * self.motion_penalty
            )
            previous = self._history[-1]
            result = [
                [
                    weight * previous[y][x] + (1.0 - weight) * current[y][x]
                    for x in range(self.width)
                ]
                for y in range(self.height)
            ]
            self._remember(result)
            if weight > 0:
                self._stats["stabilized"] += self.width * self.height
            return result

    def history(self) -> tuple:
        with self._lock:
            return tuple([row[:] for row in alpha] for alpha in self._history)

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "width": self.width,
                "height": self.height,
                "key_color": list(self._key_color),
                "similarity": self.similarity,
                "softness": self.softness,
                "feather_radius": self.feather_radius,
                "history_limit": self.history_limit,
                "history": [
                    [row[:] for row in alpha] for alpha in self._history
                ],
                "stats": dict(self._stats),
                "shadow_luma": self.shadow_luma,
                "shadow_keep": self.shadow_keep,
                "history_weight": self.history_weight,
                "motion_penalty": self.motion_penalty,
            }

    @staticmethod
    def _bad_snapshot(detail) -> ChromaKeyError:
        return ChromaKeyError("CHROMA_KEY_SNAPSHOT_INVALID", detail)

    def restore(self, state: dict) -> None:
        try:
            if not isinstance(state, dict):
                raise self._bad_snapshot({"reason": "not_a_dict"})
            if (
                not _is_int(state.get("version"))
                or state["version"] != _SNAPSHOT_VERSION
            ):
                raise self._bad_snapshot({"reason": "version"})

            width = state["width"]
            height = state["height"]
            if (
                not _is_int(width)
                or width <= 0
                or not _is_int(height)
                or height <= 0
            ):
                raise self._bad_snapshot({"reason": "size"})

            key_color = _validate_color(state["key_color"])
            similarity, softness = _validate_thresholds(
                state["similarity"], state["softness"]
            )
            feather_radius = _validate_radius(state["feather_radius"])

            history_limit = state["history_limit"]
            if not _is_int(history_limit) or history_limit < 0:
                raise self._bad_snapshot({"reason": "history_limit"})

            shadow_luma = state.get("shadow_luma", self.shadow_luma)
            shadow_keep = state.get("shadow_keep", self.shadow_keep)
            history_weight = state.get("history_weight", self.history_weight)
            motion_penalty = state.get("motion_penalty", self.motion_penalty)
            if not _is_number(shadow_luma) or shadow_luma < 0:
                raise self._bad_snapshot({"reason": "shadow_luma"})
            if not _is_number(shadow_keep) or not 0 <= shadow_keep <= 1:
                raise self._bad_snapshot({"reason": "shadow_keep"})
            if not _is_number(history_weight) or not 0 <= history_weight <= 1:
                raise self._bad_snapshot({"reason": "history_weight"})
            if not _is_number(motion_penalty) or motion_penalty < 0:
                raise self._bad_snapshot({"reason": "motion_penalty"})

            raw_history = state["history"]
            if not isinstance(raw_history, (list, tuple)):
                raise self._bad_snapshot({"reason": "history_type"})
            if len(raw_history) > history_limit:
                raise self._bad_snapshot({"reason": "history_limit_exceeded"})

            history: list[list[list[float]]] = []
            for raw_alpha in raw_history:
                try:
                    if len(raw_alpha) != height:
                        raise ValueError
                    alpha: list[list[float]] = []
                    for raw_row in raw_alpha:
                        if len(raw_row) != width:
                            raise ValueError
                        row: list[float] = []
                        for value in raw_row:
                            if not _is_number(value) or not 0 <= value <= 1:
                                raise ValueError
                            row.append(float(value))
                        alpha.append(row)
                    history.append(alpha)
                except (TypeError, ValueError) as exc:
                    raise self._bad_snapshot(
                        {"reason": "history_matrix"}
                    ) from exc

            raw_stats = state["stats"]
            if not isinstance(raw_stats, dict) or set(raw_stats) != set(_STAT_KEYS):
                raise self._bad_snapshot({"reason": "stats_fields"})
            stats = {}
            for name in _STAT_KEYS:
                value = raw_stats[name]
                if not _is_int(value) or value < 0:
                    raise self._bad_snapshot(
                        {"reason": "stats_value", "name": name}
                    )
                stats[name] = value
        except ChromaKeyError as exc:
            if exc.code == "CHROMA_KEY_SNAPSHOT_INVALID":
                raise
            raise self._bad_snapshot(
                {"reason": exc.code, "detail": exc.detail}
            ) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise self._bad_snapshot(
                {"reason": "missing_or_invalid_field"}
            ) from exc

        with self._lock:
            self.width = width
            self.height = height
            self._key_color = key_color
            self.similarity = similarity
            self.softness = softness
            self.feather_radius = feather_radius
            self.history_limit = history_limit
            self.shadow_luma = float(shadow_luma)
            self.shadow_keep = float(shadow_keep)
            self.history_weight = float(history_weight)
            self.motion_penalty = float(motion_penalty)
            self._history = history
            self._stats = stats

    def reset(self) -> None:
        with self._lock:
            self._history.clear()
            self._stats = {name: 0 for name in _STAT_KEYS}
