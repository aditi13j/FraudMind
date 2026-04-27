"""
pytest configuration for FraudMind test suite.

Markers:
  llm_eval  — tests that make real LLM calls (GPT-4o).
              Excluded from the default run; opt in with:
                  pytest -m llm_eval
              Excluded by default via pytest.ini / pyproject.toml addopts,
              or pass -m "not llm_eval" explicitly.
"""

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "llm_eval: marks tests that make real OpenAI API calls (deselect with '-m not llm_eval')",
    )
