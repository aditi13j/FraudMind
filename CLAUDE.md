## CURRENT STATUS
We are refactoring from v1 architecture to v2 architecture.
Starting with Milestone 1.

## MILESTONE 1 — IN PROGRESS
Refactor all 6 specialist agents to deterministic 
Python scoring functions. Remove all LLM calls from 
specialists. Each specialist takes signals as input, 
applies weighted rules, returns score + primary_signals.
Do NOT add LLM calls to specialists under any circumstances.