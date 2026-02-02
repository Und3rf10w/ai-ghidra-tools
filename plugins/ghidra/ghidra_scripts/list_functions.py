# Ghidra script to list all functions in a program
# @category Claude.MCP
# @runtime Jython

import json
import re

def output_json(data):
    """Output JSON data between markers for parsing."""
    print("===JSON_START===")
    print(json.dumps(data))
    print("===JSON_END===")

def run():
    """Main script entry point."""
    try:
        program = currentProgram
        if program is None:
            output_json({
                "status": "error",
                "error": "No program loaded"
            })
            return

        # Get arguments: [filter_pattern, limit, offset]
        args = getScriptArgs()
        filter_pattern = None
        limit = 100  # Default limit to prevent massive responses
        offset = 0

        if args:
            # First arg can be filter pattern or "limit:N" or "offset:N"
            for arg in args:
                if arg.startswith("limit:"):
                    limit = int(arg.split(":")[1])
                elif arg.startswith("offset:"):
                    offset = int(arg.split(":")[1])
                elif arg != "":
                    filter_pattern = arg

        filter_regex = re.compile(filter_pattern) if filter_pattern else None

        # Collect functions
        fm = program.getFunctionManager()
        functions = []
        total_count = 0
        skipped = 0

        for func in fm.getFunctions(True):  # True = forward order
            name = func.getName()

            # Apply filter if specified
            if filter_regex and not filter_regex.search(name):
                continue

            total_count += 1

            # Handle offset
            if skipped < offset:
                skipped += 1
                continue

            # Handle limit
            if len(functions) >= limit:
                continue  # Keep counting total but don't add more

            func_info = {
                "name": name,
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses(),
                "signature": str(func.getSignature()),
                "calling_convention": str(func.getCallingConventionName()),
                "is_external": func.isExternal(),
                "is_thunk": func.isThunk()
            }

            # Add parameter info
            params = []
            for param in func.getParameters():
                params.append({
                    "name": param.getName(),
                    "type": str(param.getDataType()),
                    "ordinal": param.getOrdinal()
                })
            func_info["parameters"] = params

            functions.append(func_info)

        output_json({
            "status": "success",
            "total_count": total_count,
            "returned_count": len(functions),
            "offset": offset,
            "limit": limit,
            "has_more": total_count > offset + len(functions),
            "functions": functions
        })

    except Exception as e:
        output_json({
            "status": "error",
            "error": str(e)
        })

# Run the script
run()
