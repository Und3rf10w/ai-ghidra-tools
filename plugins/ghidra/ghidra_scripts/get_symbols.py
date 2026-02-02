# Ghidra script to get imported and exported symbols
# @category Claude.MCP
# @runtime Jython

import json

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
        symbol_type = args[0] if args else "all"

        symbol_table = program.getSymbolTable()
        fm = program.getFunctionManager()

        result = {
            "status": "success",
            "type": symbol_type
        }

        # Get imports
        if symbol_type in ["imports", "all"]:
            imports = []

            # Get external functions
            for func in fm.getExternalFunctions():
                ext_loc = func.getExternalLocation()
                import_info = {
                    "name": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "is_function": True
                }
                if ext_loc:
                    lib = ext_loc.getLibraryName()
                    if lib:
                        import_info["library"] = lib
                    orig_name = ext_loc.getOriginalImportedName()
                    if orig_name:
                        import_info["original_name"] = orig_name
                imports.append(import_info)

            # Also check for imported symbols from symbol table
            external_manager = program.getExternalManager()
            for lib_name in external_manager.getExternalLibraryNames():
                # Use getExternalLocations(libraryName) on the manager, not the library
                ext_loc_iter = external_manager.getExternalLocations(lib_name)
                if ext_loc_iter:
                    while ext_loc_iter.hasNext():
                        ext_loc = ext_loc_iter.next()
                        # Skip if already captured as function
                        existing = [i for i in imports if i.get("name") == ext_loc.getLabel()]
                        if not existing:
                            import_info = {
                                "name": ext_loc.getLabel(),
                                "library": lib_name,
                                "is_function": ext_loc.isFunction()
                            }
                            addr = ext_loc.getAddress()
                            if addr:
                                import_info["address"] = str(addr)
                            imports.append(import_info)

            result["imports"] = imports
            result["import_count"] = len(imports)

        # Get exports
        if symbol_type in ["exports", "all"]:
            exports = []

            # Check entry points and exported symbols
            for symbol in symbol_table.getAllSymbols(True):
                # Check if it's an entry point or exported
                if symbol.isExternalEntryPoint() or symbol.getSource().toString() == "IMPORTED":
                    continue

                # Check for export flag or entry point
                addr = symbol.getAddress()
                if addr.isExternalAddress():
                    continue

                # Get function if this is a function entry
                func = fm.getFunctionAt(addr)
                if func and func.isExternal():
                    continue

                # Check if marked as entry point
                is_entry = program.getSymbolTable().isExternalEntryPoint(addr)

                if is_entry or symbol.getName() in ["main", "_start", "entry", "DllMain", "WinMain"]:
                    export_info = {
                        "name": symbol.getName(),
                        "address": str(addr),
                        "is_function": func is not None,
                        "is_entry_point": is_entry
                    }
                    if func:
                        export_info["signature"] = str(func.getSignature())
                    exports.append(export_info)

            # Also get symbols marked as global
            for symbol in symbol_table.getAllSymbols(True):
                if symbol.isGlobal() and not symbol.isExternal():
                    addr = symbol.getAddress()
                    if addr.isExternalAddress():
                        continue
                    # Check if already added
                    existing = [e for e in exports if e.get("address") == str(addr)]
                    if existing:
                        continue
                    func = fm.getFunctionAt(addr)
                    if func and not func.isExternal():
                        export_info = {
                            "name": symbol.getName(),
                            "address": str(addr),
                            "is_function": True,
                            "is_global": True,
                            "signature": str(func.getSignature())
                        }
                        exports.append(export_info)

            result["exports"] = exports
            result["export_count"] = len(exports)

        # Get entry points specifically
        entry_points = []
        for addr in symbol_table.getExternalEntryPointIterator():
            symbol = symbol_table.getPrimarySymbol(addr)
            func = fm.getFunctionAt(addr)
            entry_info = {
                "address": str(addr),
                "name": symbol.getName() if symbol else "unknown",
                "is_function": func is not None
            }
            if func:
                entry_info["signature"] = str(func.getSignature())
            entry_points.append(entry_info)

        result["entry_points"] = entry_points
        result["entry_point_count"] = len(entry_points)

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
