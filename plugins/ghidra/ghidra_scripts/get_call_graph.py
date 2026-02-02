# Ghidra script to generate a caller/callee tree for a function
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

def get_call_graph(program, func, max_depth=3):
    """
    Generate a call graph for a function.

    Args:
        program: The Ghidra program
        func: The function to analyze
        max_depth: Maximum depth for recursive call graph (default 3)

    Returns:
        Dictionary containing callers and callees
    """
    from ghidra.util.task import ConsoleTaskMonitor
    monitor = ConsoleTaskMonitor()

    # Get functions that call this function (callers)
    callers = []
    for caller in func.getCallingFunctions(monitor):
        caller_info = {
            "name": caller.getName(),
            "address": str(caller.getEntryPoint()),
            "signature": str(caller.getSignature()),
            "is_external": caller.isExternal(),
            "is_thunk": caller.isThunk()
        }
        callers.append(caller_info)

    # Get functions that this function calls (callees)
    callees = []
    for callee in func.getCalledFunctions(monitor):
        callee_info = {
            "name": callee.getName(),
            "address": str(callee.getEntryPoint()),
            "signature": str(callee.getSignature()),
            "is_external": callee.isExternal(),
            "is_thunk": callee.isThunk()
        }
        callees.append(callee_info)

    return {
        "callers": callers,
        "callees": callees,
        "caller_count": len(callers),
        "callee_count": len(callees)
    }

def get_recursive_call_graph(program, func, depth=1, max_depth=2, visited=None):
    """
    Generate a recursive call graph with depth levels.

    Args:
        program: The Ghidra program
        func: The function to analyze
        depth: Current depth level
        max_depth: Maximum depth to traverse
        visited: Set of visited function names to avoid cycles

    Returns:
        Dictionary containing nested call graph
    """
    from ghidra.util.task import ConsoleTaskMonitor
    monitor = ConsoleTaskMonitor()

    if visited is None:
        visited = set()

    func_name = func.getName()
    if func_name in visited or depth > max_depth:
        return None

    visited.add(func_name)

    # Get callers recursively
    callers = []
    for caller in func.getCallingFunctions(monitor):
        caller_info = {
            "name": caller.getName(),
            "address": str(caller.getEntryPoint()),
            "depth": depth
        }
        if depth < max_depth and not caller.isExternal():
            nested = get_recursive_call_graph(program, caller, depth + 1, max_depth, visited.copy())
            if nested:
                caller_info["callers"] = nested.get("callers", [])
        callers.append(caller_info)

    # Get callees recursively
    callees = []
    for callee in func.getCalledFunctions(monitor):
        callee_info = {
            "name": callee.getName(),
            "address": str(callee.getEntryPoint()),
            "depth": depth
        }
        if depth < max_depth and not callee.isExternal():
            nested = get_recursive_call_graph(program, callee, depth + 1, max_depth, visited.copy())
            if nested:
                callee_info["callees"] = nested.get("callees", [])
        callees.append(callee_info)

    return {
        "callers": callers,
        "callees": callees
    }

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
                "error": "No function name or address specified"
            })
            return

        identifier = args[0]
        recursive = len(args) > 1 and args[1].lower() in ["recursive", "true", "1"]
        max_depth = 2
        if len(args) > 2:
            try:
                max_depth = int(args[2])
            except:
                pass

        # Find the function
        addr, func = find_address_or_function(program, identifier)
        if addr is None or func is None:
            output_json({
                "status": "error",
                "error": "Could not find function: " + identifier
            })
            return

        # Generate call graph
        if recursive:
            call_graph = get_recursive_call_graph(program, func, 1, max_depth)
        else:
            call_graph = get_call_graph(program, func)

        result = {
            "status": "success",
            "function": {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "signature": str(func.getSignature()),
                "size": func.getBody().getNumAddresses(),
                "is_external": func.isExternal(),
                "is_thunk": func.isThunk()
            },
            "recursive": recursive,
            "call_graph": call_graph
        }

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
