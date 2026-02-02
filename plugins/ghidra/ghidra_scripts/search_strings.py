# Ghidra script to search for strings in a program
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

        # Get arguments
        args = getScriptArgs()
        min_length = int(args[0]) if args else 4
        pattern = args[1] if len(args) > 1 else None
        pattern_regex = re.compile(pattern) if pattern else None

        # Collect strings from defined data
        listing = program.getListing()
        strings = []

        for data in listing.getDefinedData(True):
            if not data.hasStringValue():
                continue

            try:
                value = str(data.getValue())

                # Apply length filter
                if len(value) < min_length:
                    continue

                # Apply pattern filter
                if pattern_regex and not pattern_regex.search(value):
                    continue

                address = data.getAddress()

                # Get references to this string
                refs = []
                for ref in getReferencesTo(address):
                    from_addr = ref.getFromAddress()
                    # Get the function containing the reference
                    func = program.getFunctionManager().getFunctionContaining(from_addr)
                    ref_info = {
                        "from": str(from_addr),
                        "type": str(ref.getReferenceType())
                    }
                    if func:
                        ref_info["function"] = func.getName()
                    refs.append(ref_info)

                string_info = {
                    "address": str(address),
                    "value": value,
                    "length": len(value),
                    "type": str(data.getDataType()),
                    "references": refs
                }
                strings.append(string_info)

            except Exception as e:
                # Skip strings that can't be processed
                continue

        # Sort by address
        strings.sort(key=lambda x: x["address"])

        output_json({
            "status": "success",
            "string_count": len(strings),
            "min_length": min_length,
            "pattern": pattern,
            "strings": strings
        })

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

# Run the script
run()
