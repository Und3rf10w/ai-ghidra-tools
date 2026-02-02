# Ghidra script to get basic blocks (control flow graph) for a function
# @category Claude.MCP
# @runtime Jython

import json
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

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
                "error": "Usage: <function_name|address>"
            })
            return

        identifier = args[0]

        func = find_function(program, identifier)
        if func is None:
            output_json({"status": "error", "error": "Function not found: " + identifier})
            return

        # Get basic blocks
        block_model = BasicBlockModel(program)
        listing = program.getListing()
        monitor = ConsoleTaskMonitor()

        blocks = []
        block_iter = block_model.getCodeBlocksContaining(func.getBody(), monitor)

        while block_iter.hasNext():
            block = block_iter.next()

            block_info = {
                "start": str(block.getFirstStartAddress()),
                "end": str(block.getMaxAddress()),
                "name": block.getName(),
                "size": block.getNumAddresses()
            }

            # Get successors (where control can flow to)
            successors = []
            dest_iter = block.getDestinations(monitor)
            while dest_iter.hasNext():
                dest = dest_iter.next()
                dest_addr = dest.getDestinationAddress()
                if dest_addr is not None:
                    succ_info = {
                        "address": str(dest_addr),
                        "type": str(dest.getFlowType())
                    }
                    successors.append(succ_info)
            block_info["successors"] = successors

            # Get predecessors (where control can come from)
            predecessors = []
            src_iter = block.getSources(monitor)
            while src_iter.hasNext():
                src = src_iter.next()
                src_addr = src.getSourceAddress()
                if src_addr is not None:
                    pred_info = {
                        "address": str(src_addr),
                        "type": str(src.getFlowType())
                    }
                    predecessors.append(pred_info)
            block_info["predecessors"] = predecessors

            # Get instructions in this block
            instructions = []
            inst_iter = listing.getInstructions(block, True)
            while inst_iter.hasNext():
                inst = inst_iter.next()
                instructions.append({
                    "address": str(inst.getAddress()),
                    "mnemonic": inst.getMnemonicString(),
                    "text": inst.toString()
                })
            block_info["instruction_count"] = len(instructions)
            block_info["instructions"] = instructions

            blocks.append(block_info)

        # Build edge list for graph visualization
        edges = []
        for block in blocks:
            for succ in block.get("successors", []):
                edges.append({
                    "from": block["start"],
                    "to": succ["address"],
                    "type": succ["type"]
                })

        output_json({
            "status": "success",
            "function_name": func.getName(),
            "address": str(func.getEntryPoint()),
            "block_count": len(blocks),
            "edge_count": len(edges),
            "basic_blocks": blocks,
            "edges": edges
        })

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

run()
