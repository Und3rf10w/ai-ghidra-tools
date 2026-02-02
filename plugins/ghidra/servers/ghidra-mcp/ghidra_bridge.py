"""
Ghidra Bridge - Wrapper around Ghidra headless analyzer.

This module provides a Python interface to invoke Ghidra's analyzeHeadless
script and execute Jython scripts for analysis operations.
"""

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


class GhidraError(Exception):
    """Base exception for Ghidra operations."""
    pass


class GhidraTimeoutError(GhidraError):
    """Analysis or script execution timed out."""
    pass


class GhidraImportError(GhidraError):
    """Binary import failed."""
    pass


class GhidraScriptError(GhidraError):
    """Script execution failed."""
    pass


class GhidraBridge:
    """
    Bridge to Ghidra headless analyzer.

    Manages Ghidra projects and executes analysis scripts via the
    analyzeHeadless command-line tool.
    """

    # Markers for JSON output in script stdout
    JSON_START_MARKER = "===JSON_START==="
    JSON_END_MARKER = "===JSON_END==="

    def __init__(
        self,
        ghidra_install: Optional[str] = None,
        workspace: Optional[str] = None
    ):
        """
        Initialize the Ghidra bridge.

        Args:
            ghidra_install: Path to Ghidra installation directory.
                           Defaults to GHIDRA_INSTALL env var or ~/ghidra.
            workspace: Path to workspace for projects.
                      Defaults to GHIDRA_WORKSPACE env var or ~/.claude/ghidra-workspace.
        """
        # Resolve Ghidra installation path
        ghidra_install = ghidra_install or os.environ.get(
            "GHIDRA_INSTALL",
            os.path.expanduser("~/work/reverse/ghidra_12.0.2_PUBLIC")
        )
        self.ghidra_path = Path(ghidra_install).expanduser()

        # Resolve workspace path
        workspace = workspace or os.environ.get(
            "GHIDRA_WORKSPACE",
            os.path.expanduser("~/.claude/ghidra-workspace")
        )
        self.workspace = Path(workspace).expanduser()

        # Paths to key components
        self.analyze_headless = self.ghidra_path / "support" / "analyzeHeadless"
        self.script_dir = Path(__file__).parent.parent.parent / "ghidra_scripts"

        # Create workspace directories
        self.projects_dir = self.workspace / "projects"
        self.temp_dir = self.workspace / "temp"
        self.projects_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        # Validate Ghidra installation
        if not self.analyze_headless.exists():
            raise GhidraError(
                f"Ghidra analyzeHeadless not found at {self.analyze_headless}. "
                f"Please set GHIDRA_INSTALL to your Ghidra installation directory."
            )

    def _parse_json_output(self, stdout: str) -> Dict[str, Any]:
        """
        Parse JSON output from Ghidra script stdout.

        Scripts output JSON between marker lines for reliable parsing.

        Args:
            stdout: Full stdout from script execution.

        Returns:
            Parsed JSON data.

        Raises:
            GhidraScriptError: If JSON output cannot be found or parsed.
        """
        # Find JSON between markers
        start_idx = stdout.find(self.JSON_START_MARKER)
        end_idx = stdout.find(self.JSON_END_MARKER)

        if start_idx == -1 or end_idx == -1:
            # Try to find any JSON object in output
            json_match = re.search(r'\{[^{}]*\}', stdout, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except json.JSONDecodeError:
                    pass
            raise GhidraScriptError(
                f"Could not find JSON output markers in script output. "
                f"Stdout: {stdout[:500]}..."
            )

        json_str = stdout[start_idx + len(self.JSON_START_MARKER):end_idx].strip()

        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            raise GhidraScriptError(f"Failed to parse JSON output: {e}\nJSON: {json_str[:500]}")

    def _run_headless(
        self,
        project_dir: Path,
        project_name: str,
        args: List[str],
        timeout: int = 300,
        env: Optional[Dict[str, str]] = None
    ) -> subprocess.CompletedProcess:
        """
        Run analyzeHeadless with given arguments.

        Args:
            project_dir: Directory containing the project.
            project_name: Name of the Ghidra project.
            args: Additional arguments for analyzeHeadless.
            timeout: Maximum execution time in seconds.
            env: Additional environment variables.

        Returns:
            Completed process with stdout/stderr.

        Raises:
            GhidraTimeoutError: If execution exceeds timeout.
            GhidraError: If execution fails.
        """
        cmd = [
            str(self.analyze_headless),
            str(project_dir),
            project_name,
        ] + args

        # Set up environment
        run_env = os.environ.copy()
        run_env["GHIDRA_HEADLESS_MAXMEM"] = "4G"
        if env:
            run_env.update(env)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=run_env
            )
            return result
        except subprocess.TimeoutExpired:
            raise GhidraTimeoutError(f"Operation timed out after {timeout} seconds")
        except Exception as e:
            raise GhidraError(f"Failed to execute analyzeHeadless: {e}")

    def _get_binary_hash(self, binary_path: Path) -> str:
        """Get SHA256 hash of binary for caching."""
        sha256 = hashlib.sha256()
        with open(binary_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()[:16]

    def analyze_binary(
        self,
        binary_path: str,
        project_name: Optional[str] = None,
        timeout: int = 600
    ) -> Dict[str, Any]:
        """
        Import and analyze a binary file.

        Args:
            binary_path: Path to the binary to analyze.
            project_name: Name for the project (auto-generated if not provided).
            timeout: Maximum analysis time in seconds.

        Returns:
            Dict with program metadata (name, language, entry_point, function_count, etc.)
        """
        binary = Path(binary_path).expanduser().resolve()

        if not binary.exists():
            return {
                "status": "error",
                "error": f"Binary not found: {binary_path}"
            }

        # Generate project name from binary hash if not provided
        if project_name is None:
            binary_hash = self._get_binary_hash(binary)
            project_name = f"claude_{binary_hash}"

        # Use persistent projects directory
        project_dir = self.projects_dir

        # Build command
        args = [
            "-import", str(binary),
            "-scriptPath", str(self.script_dir),
            "-postScript", "analyze_binary.py",
            "-overwrite"  # Overwrite if project exists
        ]

        result = self._run_headless(project_dir, project_name, args, timeout=timeout)

        if result.returncode != 0 and "ERROR" in result.stderr:
            return {
                "status": "error",
                "error": f"Import failed: {result.stderr[:500]}",
                "stdout": result.stdout[:500]
            }

        try:
            data = self._parse_json_output(result.stdout)
            data["project_name"] = project_name
            data["project_dir"] = str(project_dir)
            return data
        except GhidraScriptError as e:
            return {
                "status": "error",
                "error": str(e),
                "stdout": result.stdout[:1000],
                "stderr": result.stderr[:1000]
            }

    def execute_script(
        self,
        project_name: str,
        program_name: str,
        script_name: str,
        script_args: Optional[List[str]] = None,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Execute a Ghidra script on an existing program.

        Args:
            project_name: Name of the Ghidra project.
            program_name: Name of the program in the project.
            script_name: Name of the script file to execute.
            script_args: Arguments to pass to the script.
            timeout: Maximum execution time in seconds.

        Returns:
            Parsed JSON output from the script.
        """
        project_dir = self.projects_dir

        args = [
            "-process", program_name,
            "-scriptPath", str(self.script_dir),
            "-postScript", script_name,
            "-noanalysis",
            "-readOnly"
        ]

        if script_args:
            args.extend(script_args)

        result = self._run_headless(project_dir, project_name, args, timeout=timeout)

        if result.returncode != 0 and "ERROR" in result.stderr:
            return {
                "status": "error",
                "error": f"Script execution failed: {result.stderr[:500]}"
            }

        try:
            return self._parse_json_output(result.stdout)
        except GhidraScriptError as e:
            return {
                "status": "error",
                "error": str(e),
                "stdout": result.stdout[:1000],
                "stderr": result.stderr[:1000]
            }

    def list_functions(
        self,
        project_name: str,
        program_name: str,
        filter_pattern: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        List all functions in a program.

        Args:
            project_name: Name of the Ghidra project.
            program_name: Name of the program.
            filter_pattern: Optional regex pattern to filter function names.

        Returns:
            Dict with list of functions (name, address, size, signature).
        """
        args = [filter_pattern] if filter_pattern else []
        return self.execute_script(project_name, program_name, "list_functions.py", args)

    def decompile_function(
        self,
        project_name: str,
        program_name: str,
        function: str
    ) -> Dict[str, Any]:
        """
        Decompile a function to C pseudocode.

        Args:
            project_name: Name of the Ghidra project.
            program_name: Name of the program.
            function: Function name or address (0x...).

        Returns:
            Dict with C code, signature, and local variables.
        """
        return self.execute_script(
            project_name, program_name, "decompile_function.py", [function]
        )

    def search_strings(
        self,
        project_name: str,
        program_name: str,
        min_length: int = 4,
        pattern: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Find strings in a program.

        Args:
            project_name: Name of the Ghidra project.
            program_name: Name of the program.
            min_length: Minimum string length.
            pattern: Optional regex pattern to filter strings.

        Returns:
            Dict with list of strings (address, value, references).
        """
        args = [str(min_length)]
        if pattern:
            args.append(pattern)
        return self.execute_script(project_name, program_name, "search_strings.py", args)

    def get_xrefs(
        self,
        project_name: str,
        program_name: str,
        address: str,
        direction: str = "both"
    ) -> Dict[str, Any]:
        """
        Get cross-references to/from an address.

        Args:
            project_name: Name of the Ghidra project.
            program_name: Name of the program.
            address: Address or function name.
            direction: "to", "from", or "both".

        Returns:
            Dict with list of cross-references.
        """
        return self.execute_script(
            project_name, program_name, "get_xrefs.py", [address, direction]
        )

    def get_symbols(
        self,
        project_name: str,
        program_name: str,
        symbol_type: str = "all"
    ) -> Dict[str, Any]:
        """
        Get imports and exports.

        Args:
            project_name: Name of the Ghidra project.
            program_name: Name of the program.
            symbol_type: "imports", "exports", or "all".

        Returns:
            Dict with imports and/or exports.
        """
        return self.execute_script(
            project_name, program_name, "get_symbols.py", [symbol_type]
        )
