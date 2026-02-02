# Ghidra script to get cross-references to/from an address
# @category Claude.MCP
# @runtime Jython

import json

def output_json(data):
    """Output JSON data between markers for parsing."""
    print("===JSON_START===")
    print(json.dumps(data))
    print("===JSON_END===")

def find_address_or_function(program, identifier):
    """
    Find an address by parsing string or looking up function name.

    Args:
        program: The Ghidra program
        identifier: Address string (0x...) or function name

    Returns:
        Tuple of (Address, Function or None)
    """
    fm = program.getFunctionManager()

    # Try as address first
    if identifier.startswith("0x") or identifier.startswith("0X"):
        try:
            addr = toAddr(identifier)
            func = fm.getFunctionContaining(addr)
            return (addr, func)
        except:
            pass

    # Try as function name
    for func in fm.getFunctions(True):
        if func.getName() == identifier:
            return (func.getEntryPoint(), func)

    # Try partial match
    for func in fm.getFunctions(True):
        if identifier.lower() in func.getName().lower():
            return (func.getEntryPoint(), func)

    return (None, None)

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
        if not args:
            output_json({
                "status": "error",
                "error": "No address or function specified"
            })
            return

        identifier = args[0]
        direction = args[1] if len(args) > 1 else "both"

        # Find the address
        addr, func = find_address_or_function(program, identifier)
        if addr is None:
            output_json({
                "status": "error",
                "error": "Could not find: " + identifier
            })
            return

        fm = program.getFunctionManager()
        xrefs = []

        # Get references TO this address
        if direction in ["to", "both"]:
            for ref in getReferencesTo(addr):
                from_addr = ref.getFromAddress()
                from_func = fm.getFunctionContaining(from_addr)

                xref_info = {
                    "direction": "to",
                    "from_address": str(from_addr),
                    "to_address": str(addr),
                    "type": str(ref.getReferenceType()),
                    "is_call": ref.getReferenceType().isCall(),
                    "is_jump": ref.getReferenceType().isJump(),
                    "is_data": ref.getReferenceType().isData()
                }
                if from_func:
                    xref_info["from_function"] = from_func.getName()
                if func:
                    xref_info["to_function"] = func.getName()
                xrefs.append(xref_info)

        # Get references FROM this address
        if direction in ["from", "both"]:
            for ref in getReferencesFrom(addr):
                to_addr = ref.getToAddress()
                to_func = fm.getFunctionContaining(to_addr)

                xref_info = {
                    "direction": "from",
                    "from_address": str(addr),
                    "to_address": str(to_addr),
                    "type": str(ref.getReferenceType()),
                    "is_call": ref.getReferenceType().isCall(),
                    "is_jump": ref.getReferenceType().isJump(),
                    "is_data": ref.getReferenceType().isData()
                }
                if func:
                    xref_info["from_function"] = func.getName()
                if to_func:
                    xref_info["to_function"] = to_func.getName()
                xrefs.append(xref_info)

        # If we have a function, also get calling/called functions
        calling_functions = []
        called_functions = []
        if func:
            try:
                from ghidra.util.task import ConsoleTaskMonitor
                monitor = ConsoleTaskMonitor()

                for caller in func.getCallingFunctions(monitor):
                    calling_functions.append({
                        "name": caller.getName(),
                        "address": str(caller.getEntryPoint())
                    })

                for callee in func.getCalledFunctions(monitor):
                    called_functions.append({
                        "name": callee.getName(),
                        "address": str(callee.getEntryPoint())
                    })
            except:
                pass

        result = {
            "status": "success",
            "target": identifier,
            "address": str(addr),
            "function": func.getName() if func else None,
            "direction": direction,
            "xref_count": len(xrefs),
            "xrefs": xrefs
        }

        if func:
            result["calling_functions"] = calling_functions
            result["called_functions"] = called_functions

        output_json(result)

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

# Run the script
run()
