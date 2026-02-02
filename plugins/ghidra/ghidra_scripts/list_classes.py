# Ghidra script to list classes (C++/ObjC)
# @category Claude.MCP
# @runtime Jython

import json
from ghidra.app.util import NamespaceUtils

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
        filter_pattern = args[0] if args else None

        symbol_table = program.getSymbolTable()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()

        classes = []

        # Method 1: Look for namespace symbols that represent classes
        for namespace in symbol_table.getClassNamespaces():
            class_name = namespace.getName(True)

            if filter_pattern and filter_pattern.lower() not in class_name.lower():
                continue

            class_info = {
                "name": namespace.getName(),
                "full_name": class_name,
                "address": str(namespace.getBody().getMinAddress()) if namespace.getBody() else None,
                "methods": [],
                "fields": []
            }

            # Get parent class if any
            parent = namespace.getParentNamespace()
            if parent and not parent.isGlobal():
                class_info["parent_namespace"] = parent.getName(True)

            # Find methods in this namespace
            for symbol in symbol_table.getSymbols(namespace):
                if symbol.getSymbolType().toString() == "Function":
                    func = fm.getFunctionAt(symbol.getAddress())
                    if func:
                        method_info = {
                            "name": symbol.getName(),
                            "address": str(symbol.getAddress()),
                            "signature": str(func.getSignature())
                        }
                        # Check if virtual
                        if "virtual" in str(func.getSignature()).lower():
                            method_info["is_virtual"] = True
                        class_info["methods"].append(method_info)
                elif symbol.getSymbolType().toString() == "Label":
                    # Could be a field
                    class_info["fields"].append({
                        "name": symbol.getName(),
                        "address": str(symbol.getAddress())
                    })

            if class_info["methods"] or class_info["fields"]:
                classes.append(class_info)

        # Method 2: Look for vtables (virtual function tables)
        vtables = []
        for symbol in symbol_table.getAllSymbols(True):
            name = symbol.getName()
            if "vtable" in name.lower() or "vftable" in name.lower() or name.startswith("_ZTV"):
                vtable_info = {
                    "name": name,
                    "address": str(symbol.getAddress())
                }

                # Try to read vtable entries
                addr = symbol.getAddress()
                memory = program.getMemory()
                ptr_size = program.getDefaultPointerSize()

                entries = []
                for i in range(50):  # Max 50 entries
                    try:
                        ptr_addr = addr.add(i * ptr_size)
                        ptr_bytes = []
                        for j in range(ptr_size):
                            ptr_bytes.append(memory.getByte(ptr_addr.add(j)) & 0xff)

                        ptr_value = 0
                        for j in range(ptr_size):
                            ptr_value |= ptr_bytes[j] << (j * 8)

                        if ptr_value == 0:
                            break

                        target_addr = toAddr("0x%x" % ptr_value)
                        if target_addr:
                            func = fm.getFunctionAt(target_addr)
                            if func:
                                entries.append({
                                    "index": i,
                                    "address": "0x%x" % ptr_value,
                                    "function": func.getName()
                                })
                            else:
                                # Not pointing to a function, probably end of vtable
                                if i > 0:
                                    break
                    except:
                        break

                vtable_info["entries"] = entries
                vtable_info["entry_count"] = len(entries)
                vtables.append(vtable_info)

        # Method 3: Look for structures that look like classes in data types
        class_structures = []
        for dt in dtm.getAllDataTypes():
            dt_name = dt.getName()
            dt_path = dt.getPathName()

            if filter_pattern and filter_pattern.lower() not in dt_name.lower():
                continue

            # Check if it's a structure with methods or vtable
            if hasattr(dt, 'getComponents'):
                try:
                    components = dt.getComponents()
                    if components:
                        struct_info = {
                            "name": dt_name,
                            "path": dt_path,
                            "size": dt.getLength(),
                            "fields": []
                        }
                        for comp in components:
                            struct_info["fields"].append({
                                "name": comp.getFieldName() or "(unnamed)",
                                "type": str(comp.getDataType()),
                                "offset": comp.getOffset(),
                                "size": comp.getLength()
                            })

                        # Only include if it looks like a class (has vtable pointer or complex structure)
                        if len(struct_info["fields"]) > 0:
                            first_field = struct_info["fields"][0]
                            if "vtable" in first_field.get("name", "").lower() or \
                               "vptr" in first_field.get("name", "").lower() or \
                               "*" in first_field.get("type", ""):
                                class_structures.append(struct_info)
                except:
                    pass

        output_json({
            "status": "success",
            "class_count": len(classes),
            "vtable_count": len(vtables),
            "class_structure_count": len(class_structures),
            "classes": classes,
            "vtables": vtables,
            "class_structures": class_structures[:50]  # Limit structures
        })

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

run()
