---
name: ghidra-analyze
description: Analyze a binary file with Ghidra reverse engineering framework
allowed-tools:
  - mcp__ghidra_ghidra-mcp__analyze_binary
  - mcp__ghidra_ghidra-mcp__list_functions
  - mcp__ghidra_ghidra-mcp__search_strings
---

# Ghidra Binary Analysis

Analyze the specified binary file using Ghidra.

## Arguments

- `binary_path` (required): Path to the binary file to analyze

## Process

1. Use `analyze_binary` to import and analyze the binary
2. Report the program metadata:
   - Architecture and compiler
   - Entry point address
   - Number of functions
   - Memory layout
3. Optionally list interesting functions (main, entry, etc.)
4. Optionally search for interesting strings

## Output

Provide a summary including:
- Binary format and architecture
- Entry point
- Function count
- Notable functions found
- Interesting strings (if any)

After analysis, inform the user they can:
- Use `/ghidra-decompile <function>` to decompile specific functions
- Ask to search for specific strings or patterns
- Request cross-reference analysis
