//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.sourcemap.*;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.ISF.*;
import ghidra.program.model.gclass.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
// Ghidra Script (Java): FindEbxSource.java
// 用途: 找到目标函数的所有调用者(向上递归), 并在每个调用点附近查找 EBX 赋值指令
// 使用方法: Window -> Script Manager -> 新建 Java 脚本, 类名必须叫 FindEbxSource -> 粘贴本文件内容 -> 运行
// 结果打印在 Ghidra 底部 Console 窗口
import java.util.HashSet;
import java.util.Set;

public class NewScript extends GhidraScript {

    static final String TARGET_ADDR_STR = "10004cde"; // 起点: 想知道是谁调用了这个函数
    static final int MAX_DEPTH = 4;                     // 最多向上追溯几层调用
    static final int SEARCH_WINDOW_BEFORE = 40;         // 在每个调用点前面搜多少条指令找 EBX 赋值

    Set<String> visited = new HashSet<>();

    @Override
    public void run() throws Exception {
        recurseCallers(TARGET_ADDR_STR, 0);
        println("done.");
    }

    void recurseCallers(String addrStr, int depth) throws Exception {
        if (depth > MAX_DEPTH) {
            return;
        }
        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        Function func = currentProgram.getFunctionManager().getFunctionContaining(addr);
        String fname = (func != null) ? func.getName() : "???";
        println("========== 深度 " + depth + ": 目标地址 0x" + addrStr + " (函数: " + fname + ") ==========");

        Reference[] refs = getReferencesTo(addr);
        if (refs == null || refs.length == 0) {
            println("  没有找到任何交叉引用(可能是间接调用，或者是程序入口)");
            return;
        }

        for (Reference ref : refs) {
            Address fromAddr = ref.getFromAddress();
            String key = fromAddr.toString();
            if (visited.contains(key)) {
                continue;
            }
            visited.add(key);

            Function fromFunc = currentProgram.getFunctionManager().getFunctionContaining(fromAddr);
            String fromFuncName = (fromFunc != null) ? fromFunc.getName() : "???";

            println("  <- 被调用于 0x" + fromAddr + " (所在函数: " + fromFuncName + ", 引用类型: " + ref.getReferenceType() + ")");

            findEbxAssignmentBefore(fromAddr, fromFunc);

            if (fromFunc != null) {
                recurseCallers(fromFunc.getEntryPoint().toString(), depth + 1);
            }
        }
    }

    void findEbxAssignmentBefore(Address callAddr, Function func) {
        if (func == null) {
            return;
        }
        Instruction instr = getInstructionBefore(callAddr);
        int count = 0;
        boolean found = false;
        while (instr != null && count < SEARCH_WINDOW_BEFORE && func.getBody().contains(instr.getAddress())) {
            String mnem = instr.getMnemonicString().toUpperCase();
            String opstr = instr.toString();
            if (opstr.toUpperCase().contains("EBX") &&
                (mnem.equals("MOV") || mnem.equals("LEA") || mnem.equals("POP") || mnem.equals("XOR"))) {
                println("    [可能的EBX赋值] " + instr.getAddress() + " : " + opstr);
                found = true;
            }
            instr = getInstructionBefore(instr.getAddress());
            count++;
        }
        if (!found) {
            println("    (附近" + SEARCH_WINDOW_BEFORE + "条指令内没找到明显的EBX赋值)");
        }
    }
}
