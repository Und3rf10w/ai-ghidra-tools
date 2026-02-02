# Ghidra script to get disassembly for a function or address range
# @category Claude.MCP
# @runtime Jython

import json

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
        if not args:
            output_json({
                "status": "error",
                "error": "Usage: <function_name|address> [end_address] [max_instructions]"
            })
            return

        identifier = args[0]
        end_addr_str = args[1] if len(args) > 1 else None
        max_instructions = int(args[2]) if len(args) > 2 else 500

        listing = program.getListing()
        instructions = []

        # Check if this is a range (start-end) or function/single address
        if end_addr_str and end_addr_str.startswith("0x"):
            # Address range mode
            start_addr = toAddr(identifier)
            end_addr = toAddr(end_addr_str)

            if start_addr is None or end_addr is None:
                output_json({"status": "error", "error": "Invalid address range"})
                return

            inst_iter = listing.getInstructions(start_addr, True)
            count = 0
            while inst_iter.hasNext() and count < max_instructions:
                inst = inst_iter.next()
                if inst.getAddress().compareTo(end_addr) > 0:
                    break

                inst_info = {
                    "address": str(inst.getAddress()),
                    "mnemonic": inst.getMnemonicString(),
                    "operands": inst.toString().split(" ", 1)[1] if " " in inst.toString() else "",
                    "bytes": " ".join(["%02x" % (b & 0xff) for b in inst.getBytes()]),
                    "length": inst.getLength()
                }

                # Add flow info
                flows = inst.getFlows()
                if flows:
                    inst_info["flows_to"] = [str(f) for f in flows]

                instructions.append(inst_info)
                count += 1

            output_json({
                "status": "success",
                "mode": "range",
                "start_address": str(start_addr),
                "end_address": str(end_addr),
                "instruction_count": len(instructions),
                "instructions": instructions
            })
        else:
            # Function mode
            func = find_function(program, identifier)
            if func is None:
                output_json({"status": "error", "error": "Function not found: " + identifier})
                return

            body = func.getBody()
            inst_iter = listing.getInstructions(body, True)

            count = 0
            while inst_iter.hasNext() and count < max_instructions:
                inst = inst_iter.next()

                inst_info = {
                    "address": str(inst.getAddress()),
                    "mnemonic": inst.getMnemonicString(),
                    "operands": inst.toString().split(" ", 1)[1] if " " in inst.toString() else "",
                    "bytes": " ".join(["%02x" % (b & 0xff) for b in inst.getBytes()]),
                    "length": inst.getLength()
                }

                # Add comment if present
                comment = inst.getComment(0)  # EOL comment
                if comment:
                    inst_info["comment"] = comment

                # Add flow info
                flows = inst.getFlows()
                if flows:
                    inst_info["flows_to"] = [str(f) for f in flows]

                instructions.append(inst_info)
                count += 1

            output_json({
                "status": "success",
                "mode": "function",
                "function_name": func.getName(),
                "address": str(func.getEntryPoint()),
                "signature": str(func.getSignature()),
                "instruction_count": len(instructions),
                "truncated": count >= max_instructions,
                "instructions": instructions
            })

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

run()
