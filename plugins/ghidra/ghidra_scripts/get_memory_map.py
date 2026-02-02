# Ghidra script to get memory map (sections, permissions, addresses)
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
            output_json({"status": "error", "error": "No program loaded"})
            return

        memory = program.getMemory()
        blocks = []

        for block in memory.getBlocks():
            block_info = {
                "name": block.getName(),
                "start": str(block.getStart()),
                "end": str(block.getEnd()),
                "size": block.getSize(),
                "permissions": {
                    "read": block.isRead(),
                    "write": block.isWrite(),
                    "execute": block.isExecute()
                },
                "type": str(block.getType()),
                "is_initialized": block.isInitialized(),
                "is_mapped": block.isMapped(),
                "is_loaded": block.isLoaded(),
                "is_overlay": block.isOverlay()
            }

            # Get source info if available
            source = block.getSourceName()
            if source:
                block_info["source"] = source

            # Get comment if any
            comment = block.getComment()
            if comment:
                block_info["comment"] = comment

            blocks.append(block_info)

        # Get image base
        image_base = program.getImageBase()

        # Get address spaces
        address_factory = program.getAddressFactory()
        address_spaces = []
        for space in address_factory.getAddressSpaces():
            space_info = {
                "name": space.getName(),
                "type": str(space.getType()),
                "size": space.getSize(),
                "is_memory_space": space.isMemorySpace(),
                "is_loaded_memory_space": space.isLoadedMemorySpace()
            }
            address_spaces.append(space_info)

        output_json({
            "status": "success",
            "image_base": str(image_base),
            "total_memory_size": memory.getSize(),
            "block_count": len(blocks),
            "memory_blocks": blocks,
            "address_spaces": address_spaces
        })

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

run()
