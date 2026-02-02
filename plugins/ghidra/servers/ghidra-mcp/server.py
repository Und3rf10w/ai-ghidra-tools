#!/usr/bin/env python3
"""
Ghidra MCP Server - Model Context Protocol server for Ghidra integration.

This server provides tools for binary analysis, decompilation, and
reverse engineering through Ghidra's headless analyzer.
"""

import asyncio
import json
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from ghidra_bridge import GhidraBridge, GhidraError


# Initialize MCP server
server = Server("ghidra-mcp")

# Initialize Ghidra bridge (lazy initialization)
_bridge: Optional[GhidraBridge] = None


def get_bridge() -> GhidraBridge:
    """Get or create the Ghidra bridge instance."""
    global _bridge
    if _bridge is None:
        _bridge = GhidraBridge()
    return _bridge


# Tool definitions
TOOLS = [
    Tool(
        name="analyze_binary",
        description="Import and analyze a binary file with Ghidra. Returns program metadata including architecture, entry point, and function count. This must be called before other operations on a new binary.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Absolute or relative path to the binary file to analyze"
                },
                "project_name": {
                    "type": "string",
                    "description": "Optional name for the Ghidra project. If not provided, a name is generated from the binary hash."
                },
                "timeout": {
                    "type": "integer",
                    "description": "Maximum analysis time in seconds (default: 600)",
                    "default": 600
                }
            },
            "required": ["binary_path"]
        }
    ),
    Tool(
        name="list_functions",
        description="List functions in an analyzed binary with pagination. Returns function names, addresses, sizes, and signatures. Use limit/offset for large binaries.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project (from analyze_binary result)"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project (usually the binary filename)"
                },
                "filter": {
                    "type": "string",
                    "description": "Optional regex pattern to filter function names"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of functions to return (default: 100)",
                    "default": 100
                },
                "offset": {
                    "type": "integer",
                    "description": "Number of functions to skip for pagination (default: 0)",
                    "default": 0
                }
            },
            "required": ["project_name", "program_name"]
        }
    ),
    Tool(
        name="decompile_function",
        description="Decompile a function to C pseudocode. Returns the decompiled C code, function signature, and local variables.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "function": {
                    "type": "string",
                    "description": "Function name or address (e.g., 'main' or '0x401000')"
                }
            },
            "required": ["project_name", "program_name", "function"]
        }
    ),
    Tool(
        name="search_strings",
        description="Find strings in an analyzed binary. Returns strings with their addresses and references.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "min_length": {
                    "type": "integer",
                    "description": "Minimum string length (default: 4)",
                    "default": 4
                },
                "pattern": {
                    "type": "string",
                    "description": "Optional regex pattern to filter strings"
                }
            },
            "required": ["project_name", "program_name"]
        }
    ),
    Tool(
        name="get_xrefs",
        description="Get cross-references to or from an address. Useful for understanding call graphs and data flow.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "address": {
                    "type": "string",
                    "description": "Address or function name to get references for"
                },
                "direction": {
                    "type": "string",
                    "enum": ["to", "from", "both"],
                    "description": "Direction of references: 'to' (incoming), 'from' (outgoing), or 'both'",
                    "default": "both"
                }
            },
            "required": ["project_name", "program_name", "address"]
        }
    ),
    Tool(
        name="get_symbols",
        description="Get imported and exported symbols. Shows external library dependencies and exported functions.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "type": {
                    "type": "string",
                    "enum": ["imports", "exports", "all"],
                    "description": "Type of symbols to retrieve",
                    "default": "all"
                }
            },
            "required": ["project_name", "program_name"]
        }
    ),
    Tool(
        name="get_disassembly",
        description="Get assembly instructions for a function or address range. Returns disassembled instructions with addresses and opcodes.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "function_or_address": {
                    "type": "string",
                    "description": "Function name or starting address (e.g., 'main' or '0x401000')"
                },
                "end_address": {
                    "type": "string",
                    "description": "Optional ending address for range disassembly"
                },
                "max_instructions": {
                    "type": "integer",
                    "description": "Maximum number of instructions to return (default: 100)",
                    "default": 100
                }
            },
            "required": ["project_name", "program_name", "function_or_address"]
        }
    ),
    Tool(
        name="get_memory_map",
        description="Get memory sections and their permissions. Returns information about program segments, their addresses, sizes, and permissions (read/write/execute).",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                }
            },
            "required": ["project_name", "program_name"]
        }
    ),
    Tool(
        name="search_bytes",
        description="Search for byte patterns in the binary. Useful for finding specific instructions, constants, or signatures.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "pattern": {
                    "type": "string",
                    "description": "Byte pattern to search for (hex string like 'deadbeef' or with wildcards like 'de??beef')"
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default: 100)",
                    "default": 100
                },
                "start_address": {
                    "type": "string",
                    "description": "Optional starting address for search range"
                },
                "end_address": {
                    "type": "string",
                    "description": "Optional ending address for search range"
                }
            },
            "required": ["project_name", "program_name", "pattern"]
        }
    ),
    Tool(
        name="rename_symbol",
        description="Rename a function or variable. Updates the symbol name in the Ghidra database.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "address_or_name": {
                    "type": "string",
                    "description": "Current function/variable name or address"
                },
                "new_name": {
                    "type": "string",
                    "description": "New name for the symbol"
                }
            },
            "required": ["project_name", "program_name", "address_or_name", "new_name"]
        }
    ),
    Tool(
        name="add_comment",
        description="Add a comment at a specific address. Supports different comment types (EOL, Pre, Post, Plate, Repeatable).",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "address": {
                    "type": "string",
                    "description": "Address where to add the comment"
                },
                "comment": {
                    "type": "string",
                    "description": "Comment text"
                },
                "comment_type": {
                    "type": "string",
                    "enum": ["eol", "pre", "post", "plate", "repeatable"],
                    "description": "Type of comment (default: 'eol')",
                    "default": "eol"
                }
            },
            "required": ["project_name", "program_name", "address", "comment"]
        }
    ),
    Tool(
        name="get_basic_blocks",
        description="Get the control flow graph (CFG) basic blocks for a function. Returns block addresses, sizes, and flow relationships.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "function": {
                    "type": "string",
                    "description": "Function name or address"
                }
            },
            "required": ["project_name", "program_name", "function"]
        }
    ),
    Tool(
        name="get_data_at_address",
        description="Read and interpret data at a specific address. Can read raw bytes or interpret as specific types.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "address": {
                    "type": "string",
                    "description": "Address to read data from"
                },
                "length_or_type": {
                    "type": "string",
                    "description": "Number of bytes to read or data type (e.g., '16', 'int', 'pointer', 'string')"
                },
                "format": {
                    "type": "string",
                    "enum": ["hex", "decimal", "ascii", "unicode"],
                    "description": "Output format for the data (default: 'hex')",
                    "default": "hex"
                }
            },
            "required": ["project_name", "program_name", "address"]
        }
    ),
    Tool(
        name="list_classes",
        description="List C++ or Objective-C classes found in the binary. Includes class names, methods, and vtables.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "filter": {
                    "type": "string",
                    "description": "Optional regex pattern to filter class names"
                }
            },
            "required": ["project_name", "program_name"]
        }
    ),
    Tool(
        name="set_function_signature",
        description="Update a function's signature (return type and parameters). Useful for improving decompilation quality.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "function": {
                    "type": "string",
                    "description": "Function name or address"
                },
                "signature": {
                    "type": "string",
                    "description": "New function signature (e.g., 'int foo(char* str, int len)')"
                }
            },
            "required": ["project_name", "program_name", "function", "signature"]
        }
    ),
    Tool(
        name="get_call_graph",
        description="Get the call graph (callers and callees) for a function. Returns a tree of function call relationships.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "function": {
                    "type": "string",
                    "description": "Function name or address"
                },
                "depth": {
                    "type": "integer",
                    "description": "Maximum depth for call tree traversal (default: 3)",
                    "default": 3
                }
            },
            "required": ["project_name", "program_name", "function"]
        }
    ),
    Tool(
        name="emulate_function",
        description="Execute a function using Ghidra's P-code emulator. Allows testing function behavior with custom inputs.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "function": {
                    "type": "string",
                    "description": "Function name or address"
                },
                "registers": {
                    "type": "object",
                    "description": "Initial register values (e.g., {'rdi': '0x1000', 'rsi': '0x20'})"
                },
                "memory": {
                    "type": "object",
                    "description": "Initial memory values (address -> bytes mapping)"
                },
                "max_steps": {
                    "type": "integer",
                    "description": "Maximum number of emulation steps (default: 1000)",
                    "default": 1000
                }
            },
            "required": ["project_name", "program_name", "function"]
        }
    ),
    Tool(
        name="patch_bytes",
        description="Modify bytes at a specific address in the binary. Changes are saved to the Ghidra database.",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the Ghidra project"
                },
                "program_name": {
                    "type": "string",
                    "description": "Name of the program in the project"
                },
                "address": {
                    "type": "string",
                    "description": "Address where to patch bytes"
                },
                "bytes": {
                    "type": "string",
                    "description": "Hex string of bytes to write (e.g., 'deadbeef')"
                }
            },
            "required": ["project_name", "program_name", "address", "bytes"]
        }
    )
]


@server.list_tools()
async def list_tools() -> List[Tool]:
    """Return the list of available tools."""
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """
    Handle tool calls from the MCP client.

    Args:
        name: The tool name being called.
        arguments: The arguments passed to the tool.

    Returns:
        List of TextContent with the tool results.
    """
    try:
        bridge = get_bridge()
        result: Dict[str, Any] = {}

        if name == "analyze_binary":
            result = bridge.analyze_binary(
                binary_path=arguments["binary_path"],
                project_name=arguments.get("project_name"),
                timeout=arguments.get("timeout", 600)
            )

        elif name == "list_functions":
            result = bridge.list_functions(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                filter_pattern=arguments.get("filter"),
                limit=arguments.get("limit", 100),
                offset=arguments.get("offset", 0)
            )

        elif name == "decompile_function":
            result = bridge.decompile_function(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                function=arguments["function"]
            )

        elif name == "search_strings":
            result = bridge.search_strings(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                min_length=arguments.get("min_length", 4),
                pattern=arguments.get("pattern")
            )

        elif name == "get_xrefs":
            result = bridge.get_xrefs(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                address=arguments["address"],
                direction=arguments.get("direction", "both")
            )

        elif name == "get_symbols":
            result = bridge.get_symbols(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                symbol_type=arguments.get("type", "all")
            )

        elif name == "get_disassembly":
            result = bridge.get_disassembly(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                function_or_address=arguments["function_or_address"],
                end_address=arguments.get("end_address"),
                max_instructions=arguments.get("max_instructions", 100)
            )

        elif name == "get_memory_map":
            result = bridge.get_memory_map(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"]
            )

        elif name == "search_bytes":
            result = bridge.search_bytes(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                pattern=arguments["pattern"],
                max_results=arguments.get("max_results", 100),
                start_address=arguments.get("start_address"),
                end_address=arguments.get("end_address")
            )

        elif name == "rename_symbol":
            result = bridge.rename_symbol(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                address_or_name=arguments["address_or_name"],
                new_name=arguments["new_name"]
            )

        elif name == "add_comment":
            result = bridge.add_comment(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                address=arguments["address"],
                comment=arguments["comment"],
                comment_type=arguments.get("comment_type", "eol")
            )

        elif name == "get_basic_blocks":
            result = bridge.get_basic_blocks(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                function=arguments["function"]
            )

        elif name == "get_data_at_address":
            result = bridge.get_data_at_address(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                address=arguments["address"],
                length_or_type=arguments.get("length_or_type"),
                format=arguments.get("format", "hex")
            )

        elif name == "list_classes":
            result = bridge.list_classes(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                filter_pattern=arguments.get("filter")
            )

        elif name == "set_function_signature":
            result = bridge.set_function_signature(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                function=arguments["function"],
                signature=arguments["signature"]
            )

        elif name == "get_call_graph":
            result = bridge.get_call_graph(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                function=arguments["function"],
                depth=arguments.get("depth", 3)
            )

        elif name == "emulate_function":
            result = bridge.emulate_function(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                function=arguments["function"],
                registers=arguments.get("registers"),
                memory=arguments.get("memory"),
                max_steps=arguments.get("max_steps", 1000)
            )

        elif name == "patch_bytes":
            result = bridge.patch_bytes(
                project_name=arguments["project_name"],
                program_name=arguments["program_name"],
                address=arguments["address"],
                bytes=arguments["bytes"]
            )

        else:
            result = {"status": "error", "error": f"Unknown tool: {name}"}

        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    except GhidraError as e:
        error_result = {"status": "error", "error": str(e)}
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]

    except Exception as e:
        error_result = {"status": "error", "error": f"Unexpected error: {e}"}
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
