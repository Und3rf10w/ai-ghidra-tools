"""
Pytest tests for Ghidra MCP Server.

These tests verify the MCP server tools work correctly with Ghidra's headless analyzer.
A test binary (/bin/ls) is analyzed once and reused across all tests.
"""

import json
import pytest
import sys
from pathlib import Path

# Add server path
sys.path.insert(0, str(Path(__file__).parent.parent / "servers" / "ghidra-mcp"))

from ghidra_bridge import GhidraBridge


# Fixtures
@pytest.fixture(scope="session")
def bridge():
    """Create a GhidraBridge instance."""
    return GhidraBridge()


@pytest.fixture(scope="session")
def analyzed_binary(bridge):
    """Analyze /bin/ls and return project info. Cached for session."""
    result = bridge.analyze_binary("/bin/ls", timeout=300)
    assert result.get("status") == "success", f"Analysis failed: {result.get('error')}"
    return {
        "project_name": result["project_name"],
        "program_name": result["program_name"],
        "first_function": None  # Will be populated
    }


@pytest.fixture(scope="session")
def first_function(bridge, analyzed_binary):
    """Get the first function in the binary for testing."""
    result = bridge.list_functions(
        analyzed_binary["project_name"],
        analyzed_binary["program_name"],
        limit=1
    )
    assert result.get("status") == "success"
    assert len(result.get("functions", [])) > 0
    return result["functions"][0]["name"]


# Test classes organized by feature category

class TestAnalysis:
    """Tests for binary analysis and function listing."""

    def test_analyze_binary(self, analyzed_binary):
        """Test that analyze_binary returns required fields."""
        assert analyzed_binary["project_name"]
        assert analyzed_binary["program_name"]

    def test_list_functions(self, bridge, analyzed_binary):
        """Test listing functions with pagination."""
        result = bridge.list_functions(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            limit=10,
            offset=0
        )
        assert result.get("status") == "success"
        assert result.get("total_count", 0) > 0
        assert len(result.get("functions", [])) <= 10

        # Verify function structure
        func = result["functions"][0]
        assert "name" in func
        assert "address" in func
        assert "signature" in func

    def test_list_functions_filter(self, bridge, analyzed_binary):
        """Test filtering functions by pattern."""
        result = bridge.list_functions(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            filter_pattern="FUN_",
            limit=5
        )
        assert result.get("status") == "success"
        for func in result.get("functions", []):
            assert "FUN_" in func["name"]


class TestDecompilation:
    """Tests for decompilation features."""

    def test_decompile_function(self, bridge, analyzed_binary, first_function):
        """Test decompiling a function to C."""
        result = bridge.decompile_function(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            first_function
        )
        assert result.get("status") == "success"
        assert "c_code" in result
        assert len(result["c_code"]) > 0

    def test_decompile_by_address(self, bridge, analyzed_binary):
        """Test decompiling using hex address."""
        # Get a function address first
        funcs = bridge.list_functions(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            limit=1
        )
        addr = funcs["functions"][0]["address"]

        result = bridge.decompile_function(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            f"0x{addr}"
        )
        assert result.get("status") == "success"


class TestDisassembly:
    """Tests for disassembly features."""

    def test_get_disassembly(self, bridge, analyzed_binary, first_function):
        """Test getting assembly for a function."""
        result = bridge.get_disassembly(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            first_function,
            max_instructions=20
        )
        assert result.get("status") == "success"
        assert result.get("instruction_count", 0) > 0

        inst = result["instructions"][0]
        assert "address" in inst
        assert "mnemonic" in inst
        assert "bytes" in inst


class TestMemoryAndData:
    """Tests for memory and data operations."""

    def test_get_memory_map(self, bridge, analyzed_binary):
        """Test getting memory sections."""
        result = bridge.get_memory_map(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"]
        )
        assert result.get("status") == "success"
        assert result.get("block_count", 0) > 0

        block = result["memory_blocks"][0]
        assert "name" in block
        assert "start" in block
        assert "permissions" in block

    def test_get_data_at_address(self, bridge, analyzed_binary):
        """Test reading data at an address."""
        result = bridge.get_data_at_address(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            "0x100000000",
            length_or_type="16"
        )
        assert result.get("status") == "success"
        assert "bytes" in result

    def test_get_data_as_type(self, bridge, analyzed_binary):
        """Test reading data as a specific type."""
        result = bridge.get_data_at_address(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            "0x100000000",
            length_or_type="dword"
        )
        assert result.get("status") == "success"
        assert "value" in result


class TestSearch:
    """Tests for search operations."""

    def test_search_strings(self, bridge, analyzed_binary):
        """Test searching for strings."""
        result = bridge.search_strings(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            min_length=4
        )
        assert result.get("status") == "success"
        assert len(result.get("strings", [])) > 0

    def test_search_bytes(self, bridge, analyzed_binary):
        """Test searching for byte patterns."""
        result = bridge.search_bytes(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            "55 48",  # push rbp; common x86_64 prologue
            max_results=10
        )
        assert result.get("status") == "success"
        # May or may not find matches depending on binary

    def test_search_bytes_with_wildcard(self, bridge, analyzed_binary):
        """Test searching with wildcard patterns."""
        result = bridge.search_bytes(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            "48 ?? 05",  # mov with wildcard
            max_results=5
        )
        assert result.get("status") == "success"


class TestReferences:
    """Tests for cross-reference and symbol operations."""

    def test_get_xrefs(self, bridge, analyzed_binary, first_function):
        """Test getting cross-references."""
        result = bridge.get_xrefs(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            first_function
        )
        assert result.get("status") == "success"
        # May have references_to and/or references_from

    def test_get_symbols(self, bridge, analyzed_binary):
        """Test getting imports and exports."""
        result = bridge.get_symbols(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"]
        )
        assert result.get("status") == "success"
        # Mach-O binary should have imports
        assert len(result.get("imports", [])) > 0


class TestControlFlow:
    """Tests for control flow analysis."""

    def test_get_basic_blocks(self, bridge, analyzed_binary, first_function):
        """Test getting basic blocks/CFG."""
        result = bridge.get_basic_blocks(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            first_function
        )
        assert result.get("status") == "success"
        assert result.get("block_count", 0) > 0

        block = result["basic_blocks"][0]
        assert "start" in block
        assert "instructions" in block

    def test_get_call_graph(self, bridge, analyzed_binary, first_function):
        """Test getting call graph."""
        result = bridge.get_call_graph(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            first_function
        )
        assert result.get("status") == "success"
        # May or may not have callers/callees depending on function


class TestClasses:
    """Tests for class/vtable detection (mainly for C++ binaries)."""

    def test_list_classes(self, bridge, analyzed_binary):
        """Test listing classes (may be empty for C binaries)."""
        result = bridge.list_classes(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"]
        )
        assert result.get("status") == "success"
        # ls is a C binary, so class_count may be 0


class TestEmulation:
    """Tests for P-code emulation."""

    def test_emulate_function(self, bridge, analyzed_binary, first_function):
        """Test basic emulation."""
        result = bridge.emulate_function(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            first_function,
            max_steps=10
        )
        assert result.get("status") == "success"
        assert "steps_executed" in result
        assert "execution_trace" in result


# Write operations are tested separately as they modify the program

class TestWriteOperations:
    """Tests for operations that modify the program.

    These are marked with a special marker so they can be run separately.
    """

    @pytest.mark.write
    def test_add_comment(self, bridge, analyzed_binary):
        """Test adding a comment."""
        # Get an address to comment
        funcs = bridge.list_functions(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            limit=1
        )
        addr = "0x" + funcs["functions"][0]["address"]

        result = bridge.add_comment(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            addr,
            "Test comment from pytest",
            comment_type="eol"
        )
        assert result.get("status") == "success"

    @pytest.mark.write
    def test_rename_symbol(self, bridge, analyzed_binary):
        """Test renaming a function."""
        # Get a function to rename
        funcs = bridge.list_functions(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            limit=1
        )
        original_name = funcs["functions"][0]["name"]

        # Rename it
        result = bridge.rename_symbol(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            original_name,
            "pytest_renamed_func"
        )
        assert result.get("status") == "success"

        # Rename it back
        bridge.rename_symbol(
            analyzed_binary["project_name"],
            analyzed_binary["program_name"],
            "pytest_renamed_func",
            original_name
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
