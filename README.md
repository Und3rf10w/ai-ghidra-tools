# Ghidra Plugin for Claude Code

A comprehensive reverse engineering integration that brings Ghidra's powerful binary analysis capabilities directly into Claude Code through the Model Context Protocol (MCP).

## Overview

This plugin enables Claude to analyze executables, decompile functions, search for patterns, trace cross-references, and even emulate code—all through natural language conversations. It bridges Ghidra's headless analyzer with Claude Code, making reverse engineering tasks more accessible and efficient.

### Key Capabilities

- **Binary Analysis**: Import and analyze executables, libraries, and firmware
- **Decompilation**: Convert assembly to readable C pseudocode
- **Disassembly**: View raw assembly instructions with full context
- **Pattern Searching**: Find byte sequences, strings, and signatures
- **Cross-References**: Trace data and code references throughout the binary
- **Control Flow**: Analyze basic blocks and call graphs
- **Emulation**: Execute code with Ghidra's P-code emulator
- **Annotation**: Add comments and rename symbols to document findings

## Requirements

- **Ghidra** 11.0+ (tested with 12.0.2)
- **Python** 3.9+
- **Java** 17+ (for Ghidra)
- **Claude Code** CLI

## Installation

### 1. Install Ghidra

Download and extract Ghidra from the [official releases](https://github.com/NationalSecurityAgency/ghidra/releases).

```bash
# Example: Extract to ~/ghidra
unzip ghidra_12.0.2_PUBLIC.zip -d ~/
```

### 2. Set Environment Variable

```bash
# Add to your shell profile (~/.bashrc, ~/.zshrc, etc.)
export GHIDRA_INSTALL=~/ghidra_12.0.2_PUBLIC
```

### 3. Install the Plugin

Clone or copy the plugin to your Claude Code plugins directory:

```bash
# Clone the repository
git clone https://github.com/your-org/ghidra-claude-plugin.git

# Or copy to plugins directory
cp -r ghidra ~/.claude/plugins/
```

### 4. Install Python Dependencies

```bash
cd ~/.claude/plugins/ghidra
python3 -m venv .venv
source .venv/bin/activate
pip install mcp httpx
```

### 5. Verify Installation

```bash
claude -p "analyze /bin/ls and list its functions"
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GHIDRA_INSTALL` | Path to Ghidra installation | `~/ghidra_*_PUBLIC` |
| `GHIDRA_WORKSPACE` | Directory for Ghidra projects | `~/.claude/ghidra-workspace` |

### MCP Server Configuration

The plugin's `.mcp.json` configures the MCP server:

```json
{
  "mcpServers": {
    "ghidra-mcp": {
      "command": "python3",
      "args": ["${CLAUDE_PLUGIN_ROOT}/servers/ghidra-mcp/server.py"],
      "env": {
        "GHIDRA_INSTALL": "${GHIDRA_INSTALL}",
        "GHIDRA_WORKSPACE": "${HOME}/.claude/ghidra-workspace"
      }
    }
  }
}
```

## Available Tools

### Analysis & Navigation

| Tool | Description |
|------|-------------|
| `analyze_binary` | Import and analyze a binary file. Returns metadata including architecture, entry point, and function count. **Must be called first.** |
| `list_functions` | List functions with pagination and filtering. Returns names, addresses, sizes, and signatures. |
| `get_symbols` | Get imported and exported symbols. Shows external dependencies and exports. |
| `list_classes` | List C++/Objective-C classes, vtables, and methods. |

### Decompilation & Disassembly

| Tool | Description |
|------|-------------|
| `decompile_function` | Decompile a function to C pseudocode. Returns code, signature, and local variables. |
| `get_disassembly` | Get raw assembly for a function or address range. Includes bytes, mnemonics, and operands. |
| `get_basic_blocks` | Get control flow graph with basic blocks, edges, and instructions. |

### Search & References

| Tool | Description |
|------|-------------|
| `search_strings` | Find strings in the binary with minimum length and pattern filtering. |
| `search_bytes` | Search for byte patterns with wildcard support (e.g., `48 ?? 05`). |
| `get_xrefs` | Get cross-references to/from an address. Trace callers, callees, and data refs. |
| `get_call_graph` | Get caller/callee tree for understanding function relationships. |

### Memory & Data

| Tool | Description |
|------|-------------|
| `get_memory_map` | Get memory sections with permissions and addresses. |
| `get_data_at_address` | Read and interpret data at an address (bytes, integers, pointers, strings). |

### Modification & Annotation

| Tool | Description |
|------|-------------|
| `rename_symbol` | Rename a function or symbol. Changes persist in the Ghidra project. |
| `add_comment` | Add comments at addresses (EOL, pre, post, plate, repeatable). |
| `set_function_signature` | Update function return type and parameters. |
| `patch_bytes` | Modify bytes at an address for patching or experimentation. |

### Advanced

| Tool | Description |
|------|-------------|
| `emulate_function` | Execute code using Ghidra's P-code emulator with custom register/memory inputs. |

## Usage Examples

### Basic Analysis

```
User: Analyze /bin/ls and show me its main function

Claude: [Calls analyze_binary, then decompile_function]
        Here's the decompiled main function...
```

### Finding Vulnerabilities

```
User: Search for strcpy calls in this binary

Claude: [Calls search_strings to find "strcpy", then get_xrefs]
        Found 3 calls to strcpy at addresses...
```

### Understanding Control Flow

```
User: Show me the control flow graph for the authentication function

Claude: [Calls get_basic_blocks]
        The function has 12 basic blocks with the following structure...
```

### Pattern Hunting

```
User: Find all instances of the byte pattern "48 89 e5" (mov rbp, rsp)

Claude: [Calls search_bytes]
        Found 47 matches, primarily at function prologues...
```

### Crypto Analysis with Emulation

```
User: Emulate the encrypt function with input "test"

Claude: [Calls emulate_function with memory setup]
        After 156 steps, RAX contains 0x7a3b2c1d...
```

## Project Structure

```
ghidra/
├── .claude-plugin/
│   └── plugin.json           # Plugin metadata
├── .mcp.json                  # MCP server configuration
├── servers/
│   └── ghidra-mcp/
│       ├── server.py         # MCP server implementation
│       └── ghidra_bridge.py  # Ghidra headless wrapper
├── ghidra_scripts/           # Jython scripts for Ghidra
│   ├── analyze_binary.py
│   ├── decompile_function.py
│   ├── get_disassembly.py
│   ├── search_bytes.py
│   ├── emulate_function.py
│   └── ... (18 scripts total)
├── commands/                 # Slash commands
│   ├── analyze.md
│   └── decompile.md
├── agents/                   # Specialized agents
│   └── reverse-engineer.md
├── skills/                   # Domain knowledge
│   └── ghidra-scripting/
├── tests/
│   └── test_ghidra_mcp.py   # Pytest test suite
└── README.md
```

## Development

### Running Tests

```bash
cd ~/.claude/plugins/ghidra
source .venv/bin/activate
pip install pytest

# Run read-only tests
pytest -m "not write" -v

# Run all tests (includes write operations)
pytest -v
```

### Adding New Tools

1. Create a Jython script in `ghidra_scripts/`:

```python
# @category Claude.MCP
# @runtime Jython

import json

def output_json(data):
    print("===JSON_START===")
    print(json.dumps(data))
    print("===JSON_END===")

def run():
    # Your implementation
    output_json({"status": "success", "data": result})

run()
```

2. Add wrapper method in `ghidra_bridge.py`
3. Add Tool definition in `server.py`
4. Add tests in `test_ghidra_mcp.py`

### Debugging

Enable verbose output by checking:
- Ghidra log: `~/Library/ghidra/ghidra_*/application.log`
- Script stdout: Captured in bridge's `_parse_json_output`

## Supported Architectures

The plugin supports all architectures that Ghidra supports, including:

- x86 / x86-64 (Intel/AMD)
- ARM / ARM64 (AArch64)
- MIPS / MIPS64
- PowerPC
- SPARC
- RISC-V
- 68000 (Motorola)
- 8051
- AVR
- And 20+ more

## Supported File Formats

- **Executables**: ELF, PE/COFF, Mach-O
- **Libraries**: .so, .dll, .dylib
- **Firmware**: Raw binaries, Intel HEX, Motorola S-records
- **Archives**: .a, .lib
- **Other**: DEX (Android), Java class files, PDB symbols

## Troubleshooting

### "Ghidra analyzeHeadless not found"

Ensure `GHIDRA_INSTALL` points to your Ghidra installation:

```bash
export GHIDRA_INSTALL=/path/to/ghidra_12.0.2_PUBLIC
```

### "No program loaded"

Call `analyze_binary` first before using other tools:

```
User: List functions in /bin/ls
Claude: I'll first analyze the binary, then list its functions.
        [Calls analyze_binary, then list_functions]
```

### Analysis is slow

Large binaries may take several minutes. Use the `timeout` parameter:

```python
analyze_binary("/path/to/large_binary", timeout=900)  # 15 minutes
```

### Memory issues

Increase Ghidra's heap size by setting in your environment:

```bash
export GHIDRA_HEADLESS_MAXMEM=8G
```

## Security Considerations

- This plugin executes Ghidra's headless analyzer on binaries
- Only analyze binaries from trusted sources
- The plugin creates projects in `~/.claude/ghidra-workspace/`
- Patch operations modify the Ghidra project, not the original binary

