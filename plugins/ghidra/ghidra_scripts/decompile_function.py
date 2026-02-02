# Ghidra script to decompile a function to C pseudocode
# @category Claude.MCP
# @runtime Jython

import json
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

def output_json(data):
    """Output JSON data between markers for parsing."""
    print("===JSON_START===")
    print(json.dumps(data))
    print("===JSON_END===")

def find_function(program, identifier):
    """
    Find a function by name or address.

    Args:
        program: The Ghidra program
        identifier: Function name or address string (0x...)

    Returns:
        Function object or None
    """
    fm = program.getFunctionManager()

    # Try as address first
    if identifier.startswith("0x") or identifier.startswith("0X"):
        try:
            addr = toAddr(identifier)
            func = fm.getFunctionAt(addr)
            if func:
                return func
            # Try containing function
            func = fm.getFunctionContaining(addr)
            if func:
                return func
        except:
            pass

    # Try as function name
    for func in fm.getFunctions(True):
        if func.getName() == identifier:
            return func

    # Try partial match
    for func in fm.getFunctions(True):
        if identifier.lower() in func.getName().lower():
            return func

    return None

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

        # Get function identifier from script args
        args = getScriptArgs()
        if not args:
            output_json({
                "status": "error",
                "error": "No function specified. Provide function name or address."
            })
            return

        func_identifier = args[0]

        # Find the function
        func = find_function(program, func_identifier)
        if func is None:
            output_json({
                "status": "error",
                "error": "Function not found: " + func_identifier
            })
            return

        # Initialize decompiler
        decompiler = DecompInterface()
        options = DecompileOptions()
        decompiler.setOptions(options)

        if not decompiler.openProgram(program):
            output_json({
                "status": "error",
                "error": "Failed to initialize decompiler"
            })
            return

        try:
            # Decompile the function
            monitor = ConsoleTaskMonitor()
            results = decompiler.decompileFunction(func, 60, monitor)

            if not results.decompileCompleted():
                output_json({
                    "status": "error",
                    "error": "Decompilation failed: " + str(results.getErrorMessage())
                })
                return

            decomp_func = results.getDecompiledFunction()
            c_code = decomp_func.getC() if decomp_func else None

            if not c_code:
                output_json({
                    "status": "error",
                    "error": "No decompiled code produced"
                })
                return

            # Collect local variables
            local_vars = []
            high_func = results.getHighFunction()
            if high_func:
                local_symbols = high_func.getLocalSymbolMap()
                if local_symbols:
                    for symbol in local_symbols.getSymbols():
                        var_info = {
                            "name": symbol.getName(),
                            "type": str(symbol.getDataType()),
                            "size": symbol.getSize()
                        }
                        storage = symbol.getStorage()
                        if storage:
                            var_info["storage"] = str(storage)
                        local_vars.append(var_info)

            output_json({
                "status": "success",
                "function_name": func.getName(),
                "address": str(func.getEntryPoint()),
                "signature": str(func.getSignature()),
                "c_code": c_code,
                "local_variables": local_vars
            })

        finally:
            decompiler.dispose()

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

# Run the script
run()
