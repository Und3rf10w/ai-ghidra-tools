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
        description="List all functions in an analyzed binary. Returns function names, addresses, sizes, and signatures.",
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
                filter_pattern=arguments.get("filter")
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
