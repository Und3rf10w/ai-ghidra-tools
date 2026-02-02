# Ghidra script to set/update function signature
# @category Claude.MCP
# @runtime Jython

import json
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.util.parser import FunctionSignatureParser
from ghidra.program.model.listing import VariableStorage

def output_json(data):
    """Output JSON data between markers for parsing."""
    print("===JSON_START===")
    print(json.dumps(data))
    print("===JSON_END===")

def find_function(program, identifier):
    """Find a function by name or address."""
    fm = program.getFunctionManager()

    if identifier.startswith("0x") or identifier.startswith("0X"):
        try:
            addr = toAddr(identifier)
            func = fm.getFunctionAt(addr)
            if func:
                return func
            func = fm.getFunctionContaining(addr)
            if func:
                return func
        except:
            pass

    for func in fm.getFunctions(True):
        if func.getName() == identifier:
            return func

    for func in fm.getFunctions(True):
        if identifier.lower() in func.getName().lower():
            return func

    return None

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
                "error": "Usage: <function_name|address> <signature>"
            })
            return

        identifier = args[0]
        # Join remaining args in case signature had spaces
        signature_str = " ".join(args[1:])

        func = find_function(program, identifier)
        if func is None:
            output_json({"status": "error", "error": "Function not found: " + identifier})
            return

        old_signature = str(func.getSignature())

        # Parse the signature
        dtm = program.getDataTypeManager()

        try:
            parser = FunctionSignatureParser(dtm, None)
            new_sig = parser.parse(func.getSignature(), signature_str)

            if new_sig is None:
                output_json({
                    "status": "error",
                    "error": "Failed to parse signature: " + signature_str
                })
                return

            # Apply the new signature
            cmd = ApplyFunctionSignatureCmd(
                func.getEntryPoint(),
                new_sig,
                SourceType.USER_DEFINED
            )

            if cmd.applyTo(program):
                output_json({
                    "status": "success",
                    "function_name": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "old_signature": old_signature,
                    "new_signature": str(func.getSignature())
                })
            else:
                output_json({
                    "status": "error",
                    "error": "Failed to apply signature: " + str(cmd.getStatusMsg())
                })

        except Exception as parse_error:
            # Try a simpler approach - just set return type and parameters manually
            output_json({
                "status": "error",
                "error": "Signature parsing failed: " + str(parse_error),
                "hint": "Try a simpler signature like 'int function_name(int param1, char* param2)'"
            })

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

run()
