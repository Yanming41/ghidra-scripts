//Export all functions (address, name, size, callees, decompiled C, truncation flag) to JSONL
//@author Claude
//@category _NEW_
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.address.Address;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Set;

public class ExportDriverFunctions extends GhidraScript {

    static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        String outPath = "D:\\malware_analysis\\driver_functions_full_export.jsonl";
        BufferedWriter bw = new BufferedWriter(new FileWriter(outPath));

        DecompInterface decomp = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        decomp.setOptions(opts);
        decomp.openProgram(currentProgram);

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        int total = currentProgram.getFunctionManager().getFunctionCount();
        for (Function func : it) {
            if (monitor.isCancelled()) break;
            count++;
            if (count % 200 == 0) {
                println("progress: " + count + " / " + total);
            }
            Address entry = func.getEntryPoint();
            String addrStr = entry.toString().replace("0x", "");
            // strip leading zeros formatting differences; keep as-is (hex string)
            String name = func.getName();
            long size = func.getBody().getNumAddresses();

            // callees: functions called from this function (direct calls)
            Set<String> callees = new HashSet<>();
            Set<Address> calledAddrs = func.getBody().getAddresses(true) != null ? null : null;
            // Use reference-based approach: iterate instructions, get CALL refs
            ghidra.program.model.listing.InstructionIterator instrIt =
                currentProgram.getListing().getInstructions(func.getBody(), true);
            while (instrIt.hasNext()) {
                ghidra.program.model.listing.Instruction instr = instrIt.next();
                if (instr.getFlowType().isCall()) {
                    Reference[] refs = instr.getReferencesFrom();
                    for (Reference r : refs) {
                        if (r.getReferenceType().isCall()) {
                            Function target = currentProgram.getFunctionManager()
                                .getFunctionAt(r.getToAddress());
                            if (target != null) {
                                callees.add(target.getEntryPoint().toString().replace("0x", ""));
                            } else {
                                callees.add("EXTERNAL:" + r.getToAddress().toString().replace("0x",""));
                            }
                        }
                    }
                }
            }

            String decompiled = "";
            boolean truncated = false;
            try {
                DecompileResults res = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    decompiled = res.getDecompiledFunction().getC();
                } else {
                    decompiled = "/* decompile failed or timed out */";
                    truncated = true;
                }
            } catch (Exception e) {
                decompiled = "/* decompile exception: " + e.getMessage() + " */";
                truncated = true;
            }
            if (decompiled.length() > 6000) {
                truncated = true;
            }

            StringBuilder calleesJson = new StringBuilder("[");
            boolean first = true;
            for (String c : callees) {
                if (!first) calleesJson.append(",");
                calleesJson.append("\"").append(escapeJson(c)).append("\"");
                first = false;
            }
            calleesJson.append("]");

            String line = "{\"addr\":\"" + escapeJson(addrStr) + "\",\"name\":\"" + escapeJson(name) +
                "\",\"size\":" + size + ",\"callees\":" + calleesJson.toString() +
                ",\"decompiled\":\"" + escapeJson(decompiled) + "\",\"is_known_complete_no_truncation\":" +
                (!truncated) + "}";
            bw.write(line);
            bw.newLine();
        }
        decomp.dispose();
        bw.close();
        println("DONE. Exported " + count + " functions to " + outPath);
    }
}
