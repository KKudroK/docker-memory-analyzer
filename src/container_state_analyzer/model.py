from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Availability(str, Enum):
    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class ResultCode(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"


class Strength(str, Enum):
    DECISIVE = "decisive"
    SUPPORTING = "supporting"
    WEAK = "weak"


@dataclass(slots=True)
class Observation:
    artifact: str
    layer: str
    availability: Availability
    value: Any = None
    collector: str = "unknown"
    address: str | None = None
    source: str | None = None
    note: str | None = None
    group: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Observation":
        item = dict(data)
        item["availability"] = Availability(item.get("availability", "present"))
        return cls(**item)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["availability"] = self.availability.value
        return result


@dataclass(slots=True)
class EvidenceCase:
    case_id: str
    subject: dict[str, Any]
    observations: list[Observation]
    ground_truth: str | None = None
    environment: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceCase":
        item = dict(data)
        item["observations"] = [Observation.from_dict(v) for v in item.get("observations", [])]
        return cls(**item)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "subject": self.subject,
            "ground_truth": self.ground_truth,
            "environment": self.environment,
            "provenance": self.provenance,
            "observations": [v.to_dict() for v in self.observations],
        }

    def index(self) -> dict[str, Observation]:
        ranked = {
            Availability.UNKNOWN: 0,
            Availability.ABSENT: 1,
            Availability.PRESENT: 2,
        }
        result: dict[str, Observation] = {}
        for observation in self.observations:
            current = result.get(observation.artifact)
            if current is None or ranked[observation.availability] > ranked[current.availability]:
                result[observation.artifact] = observation
        return result


@dataclass(slots=True)
class ConditionResult:
    condition_id: str
    state: str
    artifact: str
    layer: str
    result: ResultCode
    strength: Strength
    polarity: str
    group: str
    expected: Any
    actual: Any
    reason: str
    collector: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["result"] = self.result.value
        result["strength"] = self.strength.value
        return result

