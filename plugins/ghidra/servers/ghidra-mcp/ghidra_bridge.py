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

        # JVM heap size — configurable via env var
        self.max_memory = os.environ.get("GHIDRA_HEADLESS_MAXMEM", "4G")

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
        run_env["GHIDRA_HEADLESS_MAXMEM"] = self.max_memory
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
        timeout: int = 600,
        force: bool = False,
        analysis_mode: str = "default"
    ) -> Dict[str, Any]:
        """
        Import and analyze a binary file.

        If the project already exists (from a previous analysis), returns
        cached metadata without re-importing. Use force=True to re-import.

        Args:
            binary_path: Path to the binary to analyze.
            project_name: Name for the project (auto-generated if not provided).
            timeout: Maximum analysis time in seconds.
            force: If True, re-import even if the project already exists.
            analysis_mode: "default" for full analysis, "minimal" to skip
                          heavy analyzers (faster for large binaries).

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
        program_name = binary.name

        # Check if project already exists (cache hit)
        gpr_file = project_dir / f"{project_name}.gpr"
        if gpr_file.exists() and not force:
            # Project exists — just collect metadata without re-importing
            try:
                data = self.execute_script(
                    project_name, program_name, "analyze_binary.py"
                )
                data["project_name"] = project_name
                data["project_dir"] = str(project_dir)
                data["cached"] = True
                return data
            except (GhidraError, Exception):
                # Cache is corrupt — fall through to re-import
                pass

        # Build import command
        args = [
            "-import", str(binary),
            "-scriptPath", str(self.script_dir),
        ]

        # Add preScript for minimal analysis mode
        if analysis_mode == "minimal":
            args.extend(["-preScript", "set_analysis_options.py", "minimal"])
            args.extend(["-analysisTimeoutPerFile", "300"])
            args.extend(["-max-cpu", "4"])

        args.extend(["-postScript", "analyze_binary.py"])

        # Overwrite only if forcing re-import of an existing project
        if gpr_file.exists():
            args.append("-overwrite")

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
        timeout: int = 300,
        read_only: bool = True
    ) -> Dict[str, Any]:
        """
        Execute a Ghidra script on an existing program.

        Args:
            project_name: Name of the Ghidra project.
            program_name: Name of the program in the project.
            script_name: Name of the script file to execute.
            script_args: Arguments to pass to the script.
            timeout: Maximum execution time in seconds.
            read_only: Whether to open program in read-only mode (default True).

        Returns:
            Parsed JSON output from the script.
        """
        project_dir = self.projects_dir

        args = [
            "-process", program_name,
            "-scriptPath", str(self.script_dir),
            "-postScript", script_name,
        ]

        # Script args must immediately follow the script name
        if script_args:
            args.extend(script_args)

        # These flags come after script and its arguments
        args.append("-noanalysis")
        if read_only:
            args.append("-readOnly")

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
        filter_pattern: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """List functions in a program with pagination."""
        args = []
        if filter_pattern:
            args.append(filter_pattern)
        args.append(f"limit:{limit}")
        args.append(f"offset:{offset}")
        return self.execute_script(project_name, program_name, "list_functions.py", args)

    def decompile_function(
        self,
        project_name: str,
        program_name: str,
        function: str
    ) -> Dict[str, Any]:
        """Decompile a function to C pseudocode."""
        return self.execute_script(
            project_name, program_name, "decompile_function.py", [function],
            timeout=120
        )

    def search_strings(
        self,
        project_name: str,
        program_name: str,
        min_length: int = 4,
        pattern: Optional[str] = None
    ) -> Dict[str, Any]:
        """Find strings in a program."""
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
        """Get cross-references to/from an address."""
        return self.execute_script(
            project_name, program_name, "get_xrefs.py", [address, direction]
        )

    def get_symbols(
        self,
        project_name: str,
        program_name: str,
        symbol_type: str = "all"
    ) -> Dict[str, Any]:
        """Get imports and exports."""
        return self.execute_script(
            project_name, program_name, "get_symbols.py", [symbol_type]
        )

    def get_disassembly(
        self,
        project_name: str,
        program_name: str,
        identifier: str,
        end_address: Optional[str] = None,
        max_instructions: int = 500
    ) -> Dict[str, Any]:
        """Get disassembly listing for a function or address range."""
        # Script expects: args[0]=identifier, args[1]=end_address, args[2]=max_instructions
        args = [identifier]
        if end_address:
            args.append(end_address)
        else:
            args.append("")  # placeholder so max_instructions lands at args[2]
        args.append(str(max_instructions))
        return self.execute_script(
            project_name, program_name, "get_disassembly.py", args
        )

    def get_memory_map(
        self,
        project_name: str,
        program_name: str
    ) -> Dict[str, Any]:
        """Get memory map showing all memory regions."""
        return self.execute_script(
            project_name, program_name, "get_memory_map.py"
        )

    def search_bytes(
        self,
        project_name: str,
        program_name: str,
        pattern: str,
        max_results: int = 100,
        start_address: Optional[str] = None,
        end_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """Search for byte patterns in memory."""
        args = [pattern, str(max_results)]
        if start_address:
            args.append(start_address)
        if end_address:
            args.append(end_address)
        return self.execute_script(
            project_name, program_name, "search_bytes.py", args
        )

    def rename_symbol(
        self,
        project_name: str,
        program_name: str,
        identifier: str,
        new_name: str
    ) -> Dict[str, Any]:
        """Rename a function or symbol."""
        return self.execute_script(
            project_name, program_name, "rename_symbol.py",
            [identifier, new_name],
            read_only=False
        )

    def add_comment(
        self,
        project_name: str,
        program_name: str,
        address: str,
        comment: str,
        comment_type: str = "eol"
    ) -> Dict[str, Any]:
        """Add a comment at an address."""
        return self.execute_script(
            project_name, program_name, "add_comment.py",
            [address, comment, comment_type],
            read_only=False
        )

    def get_basic_blocks(
        self,
        project_name: str,
        program_name: str,
        function: str
    ) -> Dict[str, Any]:
        """Get basic blocks of a function."""
        return self.execute_script(
            project_name, program_name, "get_basic_blocks.py", [function]
        )

    def get_data_at_address(
        self,
        project_name: str,
        program_name: str,
        address: str,
        length_or_type: str = "32",
        format_type: str = "hex"
    ) -> Dict[str, Any]:
        """Read data at a specific address."""
        return self.execute_script(
            project_name, program_name, "get_data_at_address.py",
            [address, length_or_type, format_type]
        )

    def list_classes(
        self,
        project_name: str,
        program_name: str,
        filter_pattern: Optional[str] = None
    ) -> Dict[str, Any]:
        """List classes and namespaces in the program."""
        args = []
        if filter_pattern:
            args.append(filter_pattern)
        return self.execute_script(
            project_name, program_name, "list_classes.py", args
        )

    def set_function_signature(
        self,
        project_name: str,
        program_name: str,
        function: str,
        signature: str
    ) -> Dict[str, Any]:
        """Set or update function signature."""
        return self.execute_script(
            project_name, program_name, "set_function_signature.py",
            [function, signature],
            read_only=False
        )

    def get_call_graph(
        self,
        project_name: str,
        program_name: str,
        function: str,
        depth: int = 2
    ) -> Dict[str, Any]:
        """Get call graph showing functions called by and calling this function."""
        # Script expects: args[0]=function, args[1]="recursive" flag, args[2]=depth
        args = [function]
        if depth > 1:
            args.extend(["recursive", str(depth)])
        return self.execute_script(
            project_name, program_name, "get_call_graph.py", args
        )

    def emulate_function(
        self,
        project_name: str,
        program_name: str,
        function: str,
        registers: Optional[Any] = None,
        memory: Optional[Any] = None,
        max_steps: int = 1000
    ) -> Dict[str, Any]:
        """Emulate function execution with P-code emulator."""
        # Serialize dicts to JSON strings for the script
        reg_str = json.dumps(registers) if registers else "{}"
        mem_str = json.dumps(memory) if memory else "{}"
        args = [function, reg_str, mem_str, str(max_steps)]
        return self.execute_script(
            project_name, program_name, "emulate_function.py", args
        )

    def patch_bytes(
        self,
        project_name: str,
        program_name: str,
        address: str,
        hex_bytes: str
    ) -> Dict[str, Any]:
        """Patch bytes at a specific address."""
        return self.execute_script(
            project_name, program_name, "patch_bytes.py",
            [address, hex_bytes],
            read_only=False
        )
