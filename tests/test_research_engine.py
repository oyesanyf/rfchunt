"""
Consolidated Protocol Research Engine test suite covering Modules 1-12 and orchestration.
Resolves tests/test_research_engine.py specification in ORIGINAL_REQUEST.md.
"""

from tests.test_engine_12_modules import (
    test_mod1_abnf_extraction_and_inversions,
    test_mod2_bandit_and_genetic_scheduler,
    test_mod3_semantic_compiler,
    test_mod4_differential_oracle,
    test_mod5_stateful_sequence_engine,
    test_mod6_errata_tracker,
    test_mod7_metamorphic_engine,
    test_mod8_delta_debugger,
    test_mod9_causal_classifier,
    test_mod10_cross_protocol_boundary,
    test_mod11_knowledge_graph,
    test_mod12_defensive_publisher,
    test_orchestrator_rfc_ingestion,
    test_orchestrator_end_to_end_research_cycle,
)

__all__ = [
    "test_mod1_abnf_extraction_and_inversions",
    "test_mod2_bandit_and_genetic_scheduler",
    "test_mod3_semantic_compiler",
    "test_mod4_differential_oracle",
    "test_mod5_stateful_sequence_engine",
    "test_mod6_errata_tracker",
    "test_mod7_metamorphic_engine",
    "test_mod8_delta_debugger",
    "test_mod9_causal_classifier",
    "test_mod10_cross_protocol_boundary",
    "test_mod11_knowledge_graph",
    "test_mod12_defensive_publisher",
    "test_orchestrator_rfc_ingestion",
    "test_orchestrator_end_to_end_research_cycle",
]
