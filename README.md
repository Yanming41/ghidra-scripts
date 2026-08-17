# ghidra-scripts

Small Ghidra script collection for reverse-engineering experiments.

## Scripts

- `ExportDriverFunctions.java`: exports function metadata, callees, decompiled C text, and truncation status to JSONL from the current Ghidra program.
- `find_ebx_source.py`: Jython helper that recursively traces callers of a target address and looks for nearby EBX assignments.
- `NewScript.java`: Java version of the EBX caller/source tracing experiment.

## Usage

Open Ghidra Script Manager, create or import the script, adjust the hard-coded target address or output path as needed, then run it against the active program.

For `ExportDriverFunctions.java`, review the `outPath` value before running so exports are written to the intended local analysis directory.

## Repository Notes

This repository stores scripts only. Generated exports, logs, reports, environment files, and analysis output are ignored.
