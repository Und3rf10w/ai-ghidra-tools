---
name: Ghidra Scripting
description: This skill should be used when the user asks to "write a Ghidra script", "create a Ghidra analyzer", "automate Ghidra analysis", "use GhidraScript API", "access FlatProgramAPI", "decompile with DecompInterface", or needs guidance on Ghidra's Python/Jython scripting capabilities. Provides comprehensive guidance for writing Ghidra automation scripts.
version: 1.0.0
---

# Ghidra Scripting Guide

This skill provides guidance for writing Ghidra scripts using Python/Jython to automate reverse engineering tasks.

## Script Types

### Jython Scripts (Python 2.7)
- Runtime tag: `# @runtime Jython`
- Direct Java integration
- Use explicit getters: `program.getName()`

### PyGhidra Scripts (Python 3)
- Runtime tag: `# @runtime PyGhidra`
- Modern Python syntax
- Automatic property access: `program.name`

## Script Template

```python
# My Analysis Script
# @category Analysis
# @runtime Jython

def run():
    program = currentProgram
    if program is None:
        println("No program loaded")
        return

    # Your analysis code here
    fm = program.getFunctionManager()
    for func in fm.getFunctions(True):
        println(func.getName())

run()
```

## Key Global Variables

Available in all GhidraScript-based scripts:

| Variable | Description |
|----------|-------------|
| `currentProgram` | Active program being analyzed |
| `currentAddress` | Current cursor location |
| `currentLocation` | Current ProgramLocation |
| `currentSelection` | Selected address range |
| `monitor` | TaskMonitor for progress/cancellation |
| `state` | GhidraState with tool access |

## FlatProgramAPI Methods

### Address Operations
```python
addr = toAddr("0x401000")       # Parse address string
addr = toAddr(0x401000)         # From integer
```

### Function Operations
```python
func = getFunctionAt(addr)           # Exact address
func = getFunctionContaining(addr)   # Any address in function
func = getFirstFunction()            # First in program
func = getFunctionAfter(func)        # Next function
func = getFunction("main")           # By name
```

### Reference Operations
```python
refs = getReferencesTo(addr)     # Incoming references
refs = getReferencesFrom(addr)   # Outgoing references
```

### Memory Operations
```python
blocks = getMemoryBlocks()       # All memory blocks
data = getBytes(addr, length)    # Read bytes
```

### Symbol Operations
```python
symbol = getSymbolAt(addr)       # Primary symbol
symbols = getSymbols("name", namespace)
createLabel(addr, "my_label", True)
```

## Decompilation

```python
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

def decompile_function(func):
    decompiler = DecompInterface()
    decompiler.setOptions(DecompileOptions())
    decompiler.openProgram(currentProgram)

    try:
        monitor = ConsoleTaskMonitor()
        results = decompiler.decompileFunction(func, 60, monitor)

        if results.decompileCompleted():
            return results.getDecompiledFunction().getC()
        return None
    finally:
        decompiler.dispose()
```

## Common Patterns

### Iterate All Functions
```python
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    println("%s @ %s" % (func.getName(), func.getEntryPoint()))
```

### Find Strings
```python
listing = currentProgram.getListing()
for data in listing.getDefinedData(True):
    if data.hasStringValue():
        println("%s: %s" % (data.getAddress(), data.getValue()))
```

### Find Cross-References
```python
for ref in getReferencesTo(addr):
    from_addr = ref.getFromAddress()
    ref_type = ref.getReferenceType()
    println("From %s (%s)" % (from_addr, ref_type))
```

### Get Imports
```python
for func in currentProgram.getFunctionManager().getExternalFunctions():
    ext_loc = func.getExternalLocation()
    lib = ext_loc.getLibraryName() if ext_loc else "unknown"
    println("%s from %s" % (func.getName(), lib))
```

## Headless Script Execution

Run scripts via analyzeHeadless:

```bash
analyzeHeadless /project/dir ProjectName \
    -import /path/to/binary \
    -postScript MyScript.py arg1 arg2 \
    -scriptlog /tmp/script.log
```

Access arguments:
```python
args = getScriptArgs()
if args:
    target = args[0]
```

## JSON Output Pattern

For scripts that output structured data:

```python
import json

def output_json(data):
    print("===JSON_START===")
    print(json.dumps(data))
    print("===JSON_END===")

result = {"functions": [...], "status": "success"}
output_json(result)
```

## Best Practices

1. **Check for null**: Always verify `currentProgram` is not None
2. **Use monitors**: Pass `monitor` to long operations for cancellation
3. **Handle errors**: Wrap operations in try/except
4. **Clean up resources**: Dispose decompilers and close files
5. **Use transactions**: Wrap modifications in start()/end()

## Useful Imports

```python
# Core
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.data import StringDataType

# Decompiler
from ghidra.app.decompiler import DecompInterface, DecompileOptions

# Analysis
from ghidra.app.services import AnalysisPriority
from ghidra.program.model.listing import Function

# Utilities
from ghidra.util.task import ConsoleTaskMonitor
from java.io import File
```

## Script Location

Place scripts in:
- `~/ghidra_scripts/` (user scripts)
- `<ghidra>/Ghidra/Features/Base/ghidra_scripts/` (examples)
- Custom directory with `-scriptPath` argument
