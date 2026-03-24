# Ghidra preScript to configure analysis options before auto-analysis runs
# @category Claude.MCP
# @runtime Jython

def run():
    """Configure analysis options based on mode argument."""
    args = getScriptArgs()
    mode = args[0].lower() if args else "default"

    if mode == "minimal":
        # Disable slow analyzers to speed up import of large binaries.
        # Strings, symbols, functions, and basic disassembly still work.
        heavy_analyzers = [
            "Decompiler Parameter ID",
            "Stack",
            "Aggressive Instruction Finder",
            "Condense Filler Bytes",
            "DWARF",
            "PDB Universal",
            "PDB",
            "Demangler GNU",
            "Demangler Microsoft",
            "Non-Returning Functions - Discovered",
            "Embedded Media",
            "GCC Exception Handlers",
            "Windows x86 PE Exception Handling",
        ]
        for name in heavy_analyzers:
            try:
                setAnalysisOption(currentProgram, name, "false")
            except:
                pass  # Analyzer may not exist for this architecture

run()
