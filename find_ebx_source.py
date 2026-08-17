# Ghidra Script: find_ebx_source.py
# 用途: 找到目标函数的所有调用者(向上递归), 并在每个调用点附近查找 EBX 赋值指令
# 使用方法: Window -> Script Manager -> 新建 Python 脚本 -> 粘贴本文件内容 -> 运行
# 结果会打印在 Ghidra 底部的 Console 窗口

from ghidra.program.model.symbol import RefType

TARGET_ADDR_STR = "10004cde"   # 起点: 我们想知道是谁调用了这个函数
MAX_DEPTH = 4                   # 最多向上追溯几层调用
SEARCH_WINDOW_BEFORE = 40       # 在每个调用点前面搜多少条指令找 EBX 赋值

def get_func_containing(addr):
    fm = currentProgram.getFunctionManager()
    return fm.getFunctionContaining(addr)

def find_ebx_assignment_before(call_addr):
    """在 call_addr 之前, 同一个函数内, 往回找是否有给 EBX 赋值的指令"""
    listing = currentProgram.getListing()
    func = get_func_containing(call_addr)
    if func is None:
        return None
    body = func.getBody()
    instr = listing.getInstructionBefore(call_addr)
    count = 0
    results = []
    while instr is not None and count < SEARCH_WINDOW_BEFORE and body.contains(instr.getAddress()):
        mnem = instr.getMnemonicString()
        # 找 MOV EBX, xxx 或 LEA EBX, xxx 或 POP EBX 等对 EBX 有写入的指令
        try:
            outputs = instr.getResultObjects()
        except:
            outputs = []
        opstr = instr.toString()
        if "EBX" in opstr and mnem.upper() in ("MOV", "LEA", "POP", "XOR"):
            results.append("    [可能的EBX赋值] %s : %s" % (instr.getAddress(), opstr))
        instr = instr.getPrevious()
        count += 1
    return results

def recurse_callers(addr_str, depth, visited):
    if depth > MAX_DEPTH:
        return
    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    func = get_func_containing(addr)
    fname = func.getName() if func else "???"
    print("=" * 10 + " 深度 %d: 目标地址 0x%s (函数: %s) " % (depth, addr_str, fname) + "=" * 10)

    refs = getReferencesTo(addr)
    if not refs:
        print("  没有找到任何交叉引用(可能是间接调用，或者是程序入口)")
        return

    for ref in refs:
        from_addr = ref.getFromAddress()
        ref_type = ref.getReferenceType()
        from_func = get_func_containing(from_addr)
        from_func_name = from_func.getName() if from_func else "???"
        key = str(from_addr)
        if key in visited:
            continue
        visited.add(key)

        print("  <- 被调用于 0x%s (所在函数: %s, 引用类型: %s)" % (from_addr, from_func_name, ref_type))

        ebx_hits = find_ebx_assignment_before(from_addr)
        if ebx_hits:
            for h in ebx_hits:
                print(h)
        else:
            print("    (附近%d条指令内没找到明显的EBX赋值)" % SEARCH_WINDOW_BEFORE)

        # 继续往上一层追: 这次调用点所在的函数, 又是被谁调用的
        if from_func:
            recurse_callers(str(from_func.getEntryPoint()), depth + 1, visited)

visited = set()
recurse_callers(TARGET_ADDR_STR, 0, visited)
print("done.")
