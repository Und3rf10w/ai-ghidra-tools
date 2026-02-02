# Ghidra script to rename a symbol (function, variable, label)
# @category Claude.MCP
# @runtime Jython

import json
from ghidra.program.model.symbol import SourceType

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
            output_json({"status": "error", "error": "No program loaded"})
            return

        args = getScriptArgs()
        if len(args) < 2:
            output_json({
                "status": "error",
                "error": "Usage: <address_or_current_name> <new_name>"
            })
            return

        identifier = args[0]
        new_name = args[1]

        fm = program.getFunctionManager()
        symbol_table = program.getSymbolTable()

        old_name = None
        symbol_type = None
        address = None

        # Try to find as address first
        if identifier.startswith("0x") or identifier.startswith("0X"):
            addr = toAddr(identifier)
            if addr is not None:
                # Check if it's a function
                func = fm.getFunctionAt(addr)
                if func:
                    old_name = func.getName()
                    func.setName(new_name, SourceType.USER_DEFINED)
                    symbol_type = "function"
                    address = str(addr)
                else:
                    # Try to rename the primary symbol at this address
                    symbol = symbol_table.getPrimarySymbol(addr)
                    if symbol:
                        old_name = symbol.getName()
                        symbol.setName(new_name, SourceType.USER_DEFINED)
                        symbol_type = str(symbol.getSymbolType())
                        address = str(addr)
                    else:
                        output_json({
                            "status": "error",
                            "error": "No symbol found at address: " + identifier
                        })
                        return
        else:
            # Try as function name
            for func in fm.getFunctions(True):
                if func.getName() == identifier:
                    old_name = func.getName()
                    address = str(func.getEntryPoint())
                    func.setName(new_name, SourceType.USER_DEFINED)
                    symbol_type = "function"
                    break

            # Try as symbol name if not found
            if old_name is None:
                symbols = list(symbol_table.getSymbols(identifier))
                if symbols:
                    symbol = symbols[0]
                    old_name = symbol.getName()
                    address = str(symbol.getAddress())
                    symbol.setName(new_name, SourceType.USER_DEFINED)
                    symbol_type = str(symbol.getSymbolType())

        if old_name is None:
            output_json({
                "status": "error",
                "error": "Symbol not found: " + identifier
            })
            return

        output_json({
            "status": "success",
            "old_name": old_name,
            "new_name": new_name,
            "address": address,
            "symbol_type": symbol_type
        })

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

run()
