package mbdesu.cps2.util;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.RefType;

public class M68000VectorTable {

	private static final M68000InterruptVector[] IVT = {
		new M68000InterruptVector("_SP_INIT",                        0x00),
		new M68000InterruptVector("_ENTRY_POINT",                    0x04),
		new M68000InterruptVector("_BUS_ERROR",                      0x08),
		new M68000InterruptVector("_ADDRESS_ERROR",                  0x0c),
		new M68000InterruptVector("_ILLEGAL_INSTRUCTION",            0x10),
		new M68000InterruptVector("_DIV_BY_ZERO",                    0x14),
		new M68000InterruptVector("_CHK_INSTRUCTION",                0x18),
		new M68000InterruptVector("_TRAPV_INSTRUCTION",              0x1c),
		new M68000InterruptVector("_PRIVILEGE_VIOLATION",            0x20),
		new M68000InterruptVector("_TRACE",                          0x24),
		new M68000InterruptVector("_LINE_A_1010_EMULATOR",           0x28),
		new M68000InterruptVector("_LINE_F_1111_EMULATOR",           0x2c),
		new M68000InterruptVector("_UNASSIGNED",                     0x30),
		new M68000InterruptVector("_UNASSIGNED",                     0x34),
		new M68000InterruptVector("_UNASSIGNED",                     0x38),
		new M68000InterruptVector("_UNINITIALIZED_INTERRUPT_VECTOR", 0x3c),
		new M68000InterruptVector("_UNASSIGNED",                     0x40),
		new M68000InterruptVector("_UNASSIGNED",                     0x44),
		new M68000InterruptVector("_UNASSIGNED",                     0x48),
		new M68000InterruptVector("_UNASSIGNED",                     0x4c),
		new M68000InterruptVector("_UNASSIGNED",                     0x50),
		new M68000InterruptVector("_UNASSIGNED",                     0x54),
		new M68000InterruptVector("_UNASSIGNED",                     0x58),
		new M68000InterruptVector("_UNASSIGNED",                     0x5c),
		new M68000InterruptVector("_SPURIOUS_INTERRUPT",             0x60),
		new M68000InterruptVector("_LEVEL_1_INTERRUPT_AUTOVECTOR",   0x64),
		new M68000InterruptVector("_LEVEL_2_INTERRUPT_AUTOVECTOR",   0x68),
		new M68000InterruptVector("_LEVEL_3_INTERRUPT_AUTOVECTOR",   0x6c),
		new M68000InterruptVector("_LEVEL_4_INTERRUPT_AUTOVECTOR",   0x70),
		new M68000InterruptVector("_LEVEL_5_INTERRUPT_AUTOVECTOR",   0x74),
		new M68000InterruptVector("_LEVEL_6_INTERRUPT_AUTOVECTOR",   0x78),
		new M68000InterruptVector("_LEVEL_7_INTERRUPT_AUTOVECTOR",   0x7c),
		new M68000InterruptVector("_TRAP_0_INSTRUCTION_VECTOR",      0x80),
		new M68000InterruptVector("_TRAP_1_INSTRUCTION_VECTOR",      0x84),
		new M68000InterruptVector("_TRAP_2_INSTRUCTION_VECTOR",      0x88),
		new M68000InterruptVector("_TRAP_3_INSTRUCTION_VECTOR",      0x8c),
		new M68000InterruptVector("_TRAP_4_INSTRUCTION_VECTOR",      0x90),
		new M68000InterruptVector("_TRAP_5_INSTRUCTION_VECTOR",      0x94),
		new M68000InterruptVector("_TRAP_6_INSTRUCTION_VECTOR",      0x98),
		new M68000InterruptVector("_TRAP_7_INSTRUCTION_VECTOR",      0x9c),
		new M68000InterruptVector("_TRAP_8_INSTRUCTION_VECTOR",      0xa0),
		new M68000InterruptVector("_TRAP_9_INSTRUCTION_VECTOR",      0xa4),
		new M68000InterruptVector("_TRAP_10_INSTRUCTION_VECTOR",     0xa8),
		new M68000InterruptVector("_TRAP_11_INSTRUCTION_VECTOR",     0xac),
		new M68000InterruptVector("_TRAP_12_INSTRUCTION_VECTOR",     0xb0),
		new M68000InterruptVector("_TRAP_13_INSTRUCTION_VECTOR",     0xb4),
		new M68000InterruptVector("_TRAP_14_INSTRUCTION_VECTOR",     0xb8),
		new M68000InterruptVector("_TRAP_15_INSTRUCTION_VECTOR",     0xbc)
	};

	public static void mapIvt(FlatProgramAPI api, Memory mem, Program program) {
		for (M68000InterruptVector vec : IVT) {
			try {
				Address vecAddr = api.toAddr(vec.addr);
				int ptrVal = mem.getInt(vecAddr);
				Data ptrData = api.createDWord(vecAddr);
				api.createLabel(vecAddr, vec.name, true);
				api.createMemoryReference(ptrData, api.toAddr(ptrVal), RefType.DATA);
				Address functionAddress = api.toAddr(ptrVal);
				if ("_ENTRY_POINT".equals(vec.name)) {
					api.addEntryPoint(functionAddress);
					api.createFunction(functionAddress, "main");
				} else {
					api.createFunction(functionAddress, vec.name);
				}
				new DisassembleCommand(functionAddress, null, false).applyTo(program, api.getMonitor());
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				continue;
			}
		}
	}

	private static class M68000InterruptVector {
		String name;
		int addr;

		M68000InterruptVector(String name, int addr) {
			this.name = name;
			this.addr = addr;
		}
	}

}
