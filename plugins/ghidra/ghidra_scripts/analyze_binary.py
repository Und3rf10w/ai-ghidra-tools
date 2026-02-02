# Ghidra script to analyze binary and return program metadata
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

        # Collect program metadata
        result = {
            "status": "success",
            "program_name": program.getName(),
            "language": str(program.getLanguage().getLanguageID()),
            "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
            "image_base": str(program.getImageBase()),
            "min_address": str(program.getMinAddress()),
            "max_address": str(program.getMaxAddress()),
            "executable_path": program.getExecutablePath(),
            "executable_format": program.getExecutableFormat(),
            "function_count": program.getFunctionManager().getFunctionCount(),
            "memory_blocks": []
        }

        # Add MD5 if available
        try:
            result["md5"] = program.getExecutableMD5()
        except:
            pass

        # Collect memory block information
        for block in program.getMemory().getBlocks():
            block_info = {
                "name": block.getName(),
                "start": str(block.getStart()),
                "end": str(block.getEnd()),
                "size": block.getSize(),
                "read": block.isRead(),
                "write": block.isWrite(),
                "execute": block.isExecute(),
                "initialized": block.isInitialized()
            }
            result["memory_blocks"].append(block_info)

        output_json(result)

    except Exception as e:
        output_json({
            "status": "error",
            "error": str(e)
        })

# Run the script
run()
