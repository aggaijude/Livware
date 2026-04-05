"""
ml_model.py — Machine Learning malware prediction engine.

Loads a pre-trained model (joblib/pickle) and predicts the probability
that a given feature vector represents malware.
"""

from __future__ import annotations

import os
from typing import Optional

import joblib
import numpy as np

from config import MODEL_PATH, ML_MALWARE_THRESHOLD, ML_WARNING_THRESHOLD


class MLModel:
    """Singleton wrapper around the pre-trained malware classification model."""

    _instance: Optional["MLModel"] = None

    def __new__(cls) -> "MLModel":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
        return cls._instance

    def __init__(self) -> None:
        if self._loaded:
            return
        self._model = None
        self._available = False
        self._load()

    # ── Internal ────────────────────────────────────────────────────

    def _load(self) -> None:
        """Attempt to load the model file."""
        if not os.path.isfile(MODEL_PATH):
            print(f"[ml_model] Model file not found: {MODEL_PATH}")
            self._loaded = True
            return
        try:
            self._model = joblib.load(MODEL_PATH)
            self._available = True
            print(f"[ml_model] Model loaded successfully from {MODEL_PATH}")
        except Exception as e:
            print(f"[ml_model] Failed to load model: {e}")
        self._loaded = True

    # ── Public API ──────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Return True if the model is loaded and ready."""
        return self._available

    def predict(self, features: list[float]) -> dict:
        """
        Predict malware probability for a feature vector.

        Returns:
            {
                "risk": float (0.0–1.0),
                "label": "MALWARE" | "WARNING" | "SAFE",
                "source": "ML"
            }
        """
        if not self._available or self._model is None:
            return {"risk": 0.0, "label": "UNKNOWN", "source": "ML"}

        try:
            X = np.array(features).reshape(1, -1)

            # Try predict_proba first (classifiers)
            if hasattr(self._model, "predict_proba"):
                proba = self._model.predict_proba(X)
                # Assume class 1 = malware
                if proba.shape[1] >= 2:
                    risk = float(proba[0][1])
                else:
                    risk = float(proba[0][0])
            # Fall back to decision_function
            elif hasattr(self._model, "decision_function"):
                score = float(self._model.decision_function(X)[0])
                # Sigmoid to normalize
                risk = 1.0 / (1.0 + np.exp(-score))
            # Last resort: plain predict
            else:
                pred = float(self._model.predict(X)[0])
                risk = pred  # Assume 0–1 output

            risk = max(0.0, min(1.0, risk))

            if risk > ML_MALWARE_THRESHOLD:
                label = "MALWARE"
            elif risk > ML_WARNING_THRESHOLD:
                label = "WARNING"
            else:
                label = "SAFE"

            return {"risk": round(risk, 4), "label": label, "source": "ML"}

        except Exception as e:
            print(f"[ml_model] Prediction error: {e}")
            return {"risk": 0.0, "label": "ERROR", "source": "ML"}
