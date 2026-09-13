import yaml
from pathlib import Path
from typing import Dict
from .models import SourceType


class TrustLevelCalculator:
    def __init__(self, config_path: str = "config/thresholds.yaml"):
        self.config = self._load_config(config_path)
        self.trust_scores = self.config["trust_levels"]

    def _load_config(self, config_path: str) -> Dict:
        path = Path(config_path)
        if not path.exists():
            return self._default_config()
        with open(path, "r") as f:
            return yaml.safe_load(f)

    def _default_config(self) -> Dict:
        return {
            "trust_levels": {
                "user_verified": 0.9,
                "tool_result": 0.7,
                "user_anonymous": 0.5,
                "web_document": 0.3,
                "inter_agent": 0.6,
                "system": 0.95,
            }
        }

    def calculate(self, source_type: SourceType) -> float:
        return self.trust_scores.get(source_type.value, 0.5)

    def calculate_with_history(
        self, source_type: SourceType, historical_reliability: float = 1.0
    ) -> float:
        base_trust = self.calculate(source_type)
        return min(1.0, base_trust * historical_reliability)
