---
name: ghidra-decompile
description: Decompile a function to C pseudocode using Ghidra
allowed-tools:
  - mcp__ghidra_ghidra-mcp__decompile_function
  - mcp__ghidra_ghidra-mcp__list_functions
  - mcp__ghidra_ghidra-mcp__get_xrefs
---

# Ghidra Function Decompilation

Decompile a specific function to C pseudocode.

## Arguments

- `function` (required): Function name or address (e.g., "main" or "0x401000")
- `project_name` (required): Ghidra project name (from previous analysis)
- `program_name` (required): Program name in the project (usually binary filename)

## Process

1. Use `decompile_function` to get the C pseudocode
2. If function not found, use `list_functions` to help locate it
3. Present the decompiled code with syntax highlighting
4. Optionally get cross-references to understand call context

## Output

Display:
- Function signature
- Decompiled C code in a code block
- Local variables and their types
- Calling/called functions (if relevant)

## Tips

- If analyzing a new binary, run `/ghidra-analyze` first
- Function names may be mangled in C++ binaries
- Use addresses (0x...) if function names are unclear
