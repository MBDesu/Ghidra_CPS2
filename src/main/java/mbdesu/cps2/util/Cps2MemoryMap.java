package mbdesu.cps2.util;

import java.io.InputStream;

import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Cps2MemoryMap {
	
	private static final Cps2MemoryRegion[] CPS2_MEMORY_REGIONS = {
			new Cps2MemoryRegion("ROM",                 0x0,      0x400000, 0xd),
			new Cps2MemoryRegion("output",              0x400000, 0xc,      0x6),
			new Cps2MemoryRegion("QSound RAM",          0x618000, 0x2000,   0x6),
			new Cps2MemoryRegion("Extra RAM",           0x660000, 0x4000,   0x6),
			new Cps2MemoryRegion("Unknown/RAM Enable",  0x664000, 0x2,      0x6),
			new Cps2MemoryRegion("objram1",             0x700000, 0x2000,   0x2),
			new Cps2MemoryRegion("objram2",             0x708000, 0x2000,   0x6),
			new Cps2MemoryRegion("CPS A regs",          0x800100, 0x40,     0x2),
			new Cps2MemoryRegion("CPS B regs",          0x800140, 0x40,     0x6),
			new Cps2MemoryRegion("IN0",                 0x804000, 0x2,      0x4),
			new Cps2MemoryRegion("IN1",                 0x804010, 0x2,      0x4),
			new Cps2MemoryRegion("IN2/EEPROM R",        0x804020, 0x2,      0x4),
			new Cps2MemoryRegion("QSound Volume",       0x804030, 0x2,      0x4),
			new Cps2MemoryRegion("EEPROM W",            0x804040, 0x2,      0x2),
			new Cps2MemoryRegion("Unknown",             0x8040a0, 0x2,      0x0),
			new Cps2MemoryRegion("DIP Switches",        0x8040b0, 0x3,      0x4),
			new Cps2MemoryRegion("objram bank swap",    0x8040e0, 0x2,      0x2),
			new Cps2MemoryRegion("CPS A regs (custom)", 0x804100, 0x40,     0x2),
			new Cps2MemoryRegion("CPS B regs (custom)", 0x804140, 0x40,     0x6),
			new Cps2MemoryRegion("Graphics RAM",        0x900000, 0x30000,  0x2),
			new Cps2MemoryRegion("Work RAM",            0xff0000, 0x10000,  0x6)
	};

	public static void createMemoryRegions(TaskMonitor monitor, FlatProgramAPI api, InputStream inputStream, Memory mem) {
		for (Cps2MemoryRegion memReg : CPS2_MEMORY_REGIONS) {
			try {
				MemoryBlock newBlock = null; // gross
				
				if (memReg.isInitialized) {
					newBlock = mem.createInitializedBlock(memReg.name, api.toAddr(memReg.addr), inputStream, memReg.size, monitor, false);
				} else {
					newBlock = mem.createUninitializedBlock(memReg.name, api.toAddr(memReg.addr), memReg.size, false);
				}
				
				if (newBlock != null) { // gross!!!
					newBlock.setRead(memReg.isReadable);
					newBlock.setWrite(memReg.isWritable);
					newBlock.setExecute(memReg.isExecutable);
				}
			} catch (LockException | IllegalArgumentException | MemoryConflictException
					| AddressOverflowException | CancelledException e) {
				// TODO Auto-generated catch block
				System.out.println(memReg.name);
				e.printStackTrace();
			}
		}
	}

	private static class Cps2MemoryRegion {
		String name;
		int addr;
		int size;
		boolean isInitialized;
		boolean isReadable;
		boolean isWritable;
		boolean isExecutable;

		Cps2MemoryRegion(String name, int addr, int size, int irwx) {
			this.name = name;
			this.addr = addr;
			this.size = size;
			this.isInitialized = (irwx & 0b1000) > 0;
			this.isReadable    = (irwx & 0b0100) > 0;
			this.isWritable    = (irwx & 0b0010) > 0;
			this.isExecutable  = (irwx & 0b0001) > 0;
		}
	}

}
