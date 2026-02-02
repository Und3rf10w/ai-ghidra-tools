# Ghidra script to add or update comments at addresses
# @category Claude.MCP
# @runtime Jython

import json
from ghidra.program.model.listing import CodeUnit

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
                "error": "Usage: <address> <comment> [comment_type]"
            })
            return

        address_str = args[0]
        comment_text = args[1]
        comment_type_str = args[2] if len(args) > 2 else "eol"

        # Map comment type string to Ghidra constant
        comment_types = {
            "eol": CodeUnit.EOL_COMMENT,
            "pre": CodeUnit.PRE_COMMENT,
            "post": CodeUnit.POST_COMMENT,
            "plate": CodeUnit.PLATE_COMMENT,
            "repeatable": CodeUnit.REPEATABLE_COMMENT
        }

        comment_type = comment_types.get(comment_type_str.lower())
        if comment_type is None:
            output_json({
                "status": "error",
                "error": "Invalid comment type. Use: eol, pre, post, plate, or repeatable"
            })
            return

        addr = toAddr(address_str)
        if addr is None:
            output_json({
                "status": "error",
                "error": "Invalid address: " + address_str
            })
            return

        listing = program.getListing()
        code_unit = listing.getCodeUnitAt(addr)

        if code_unit is None:
            # Try to get the code unit containing this address
            code_unit = listing.getCodeUnitContaining(addr)

        if code_unit is None:
            output_json({
                "status": "error",
                "error": "No code unit at address: " + address_str
            })
            return

        # Get old comment if any
        old_comment = code_unit.getComment(comment_type)

        # Set the new comment
        code_unit.setComment(comment_type, comment_text)

        # Get context info
        result = {
            "status": "success",
            "address": str(addr),
            "comment": comment_text,
            "comment_type": comment_type_str,
            "old_comment": old_comment
        }

        # Add instruction context if applicable
        inst = listing.getInstructionAt(addr)
        if inst:
            result["instruction"] = inst.toString()

        # Add function context if applicable
        fm = program.getFunctionManager()
        func = fm.getFunctionContaining(addr)
        if func:
            result["function"] = func.getName()

        output_json(result)

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

run()
