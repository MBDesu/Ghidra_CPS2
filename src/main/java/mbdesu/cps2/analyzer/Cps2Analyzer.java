package mbdesu.cps2.analyzer;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.StreamSupport;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import mbdesu.cps2.util.InstructionWrapper;

public class Cps2Analyzer extends AbstractAnalyzer {

	public Cps2Analyzer() {
		super("CPS2 Jump Tables", "Analyze CPS2 jump tables", AnalyzerType.INSTRUCTION_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		return super.removed(program, set, monitor, log);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getLanguageID().toString().startsWith("68000");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
	}

	@Override
	public void analysisEnded(Program program) {
		// TODO Auto-generated method stub
		super.analysisEnded(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		super.registerOptions(options, program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AutoAnalysisManager autoAnalysisManager = AutoAnalysisManager.getAnalysisManager(program);
		ConsoleService consoleService = autoAnalysisManager.getAnalysisTool().getService(ConsoleService.class);
		FlatProgramAPI api = new FlatProgramAPI(program);

		StreamSupport.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
			.forEach(function -> {
				AddressSetView range = function.getBody();
				InstructionIterator instructionIterator = program.getListing().getInstructions(range, true);
				StreamSupport.stream(instructionIterator.spliterator(), false)
					.filter(instruction -> {
						if (!instruction.getFlowType().isComputed()) return false; // we're only interested in computed jumps/calls

						Reference[] refs = instruction.getReferencesFrom();

						for (Reference ref : refs) {
							RefType refType = ref.getReferenceType();
							if (refType.isFlow() && !refType.isFallthrough() && !ref.getSource().equals(SourceType.ANALYSIS)) { // we don't wanna analyze already analyzed jump tables
								return false;
							}
						}

						return true;
					})
					.map(InstructionWrapper::new)
					.forEach(computedJump -> {
						String computedJumpAddrString = computedJump.instruction.getAddressString(true, true);
						consoleService.addMessage("Cps2Analyzer", "Computed jump found at " + computedJumpAddrString);
						consoleService.addMessage("Cps2Analyzer", computedJump.toString());

						if (this.createJumpTable(program, function, monitor, computedJump)) {
							consoleService.addMessage("Cps2Analyzer", "Created jump table");
						} else {
							api.createBookmark(computedJump.instruction.getAddress(), "UNRECOVERED_JUMP", "Manual intervention required to fix jump table");
							consoleService.addMessage("Cps2Analyzer", "Failed to create jump table; see bookmark at " + computedJumpAddrString);
						}

					});
			});
		return true;
	}

	private boolean createJumpTable(Program program, Function function, TaskMonitor monitor, InstructionWrapper computedJump) {
		JumpTableMetadata jtm = this.getJumpTableMetadata(program, computedJump);
		if (jtm == null) return false;
		
		switch (jtm.computedJumpType) {
			case INDEXED:
				try {
					return this.createIndexedJumpTable(program, function, monitor, jtm, computedJump);
				} catch (Exception e) {
					return false;
				}
			// fallthrough
			case DIRECT:
			default:
				return false;
		}
	}

	private JumpTableMetadata getJumpTableMetadata(Program program, InstructionWrapper computedJump) {
		ComputedJumpType computedJumpType = ComputedJumpType.INDEXED;
		int numOperands = computedJump.instruction.getOpObjects(0).length;

		// number of operands might not be the best heuristic to determine the
		// type of jump being performed; may need re-evaluation later
		if (numOperands == 1) {
			computedJumpType = ComputedJumpType.DIRECT;
		} else if (numOperands > 1) {
			computedJumpType = ComputedJumpType.INDEXED;
		} else {
			return null;
		}

		switch (computedJumpType) {
			case INDEXED:
				return this.getIndexedJumpTableMetadata(program, computedJump);
			case DIRECT:
				return null;
			default:
				return null;
		}
	}

	private JumpTableMetadata getIndexedJumpTableMetadata(Program program, InstructionWrapper computedJump) {
		FlatProgramAPI api = new FlatProgramAPI(program);
		Object[] operandObjects = computedJump.instruction.getOpObjects(0);

		// get the jump table address and the indexing register...
		Address jumpTableAddress = null;
		Register indexRegister = null;
		for (Object operand : operandObjects) {
			if (operand instanceof Scalar && ((Scalar) operand).getValue() > 1L) {
				Scalar s = (Scalar) operand;
				jumpTableAddress = api.toAddr(s.getUnsignedValue());
			} else if (operand instanceof Register && !((Register) operand).isProgramCounter()) {
				indexRegister = (Register) operand;
			}
		}
		if (jumpTableAddress == null || indexRegister == null) return null;

		// ...and use them to find the instruction that computes the jump,
		// using it to determine the size of jump table entries
		InstructionWrapper candidateInstruction = new InstructionWrapper(computedJump.instruction.getPrevious());
		while (candidateInstruction.instruction != null) {
			if (candidateInstruction.instruction == null) break;
			else if (candidateInstruction.isMove()) {
				Object[] ciSourceOperands = candidateInstruction.instruction.getOpObjects(0);
				Object[] ciDestinationOperands = candidateInstruction.instruction.getOpObjects(1);

				Address sourceAddress = null;
				Register destinationRegister = null;
				for (Object operand : ciSourceOperands) {
					if (operand instanceof Scalar && ((Scalar) operand).getValue() > 1L) {
						sourceAddress = api.toAddr(((Scalar) operand).getUnsignedValue());
					}
				}
				destinationRegister = ciDestinationOperands[0] instanceof Register ? (Register) ciDestinationOperands[0] : null;

				if (sourceAddress != null && destinationRegister != null && sourceAddress.equals(jumpTableAddress) && destinationRegister.equals(indexRegister)) {
					int jumpTableEntrySize = candidateInstruction.getJumpTableSize();

					if (jumpTableEntrySize > 0) {
						return new JumpTableMetadata(jumpTableAddress, candidateInstruction.getJumpTableSize(), ComputedJumpType.INDEXED);
					}
				}
			} else {
				candidateInstruction = new InstructionWrapper(candidateInstruction.instruction.getPrevious());
			}
		}
		return null;
	}
	
	private boolean createIndexedJumpTable(Program program, Function function, TaskMonitor monitor, JumpTableMetadata jtm, InstructionWrapper computedJump) { 
		Listing listing = program.getListing();
		FlatProgramAPI api = new FlatProgramAPI(program);
		try {
			this.createDataAt(api, listing, jtm.address, jtm.dataType, jtm.size);
			int prospectiveTableSize = this.getBytesAsUnsignedInteger(listing.getDataAt(jtm.address).getBytes());
			int prospectiveNumEntries = prospectiveTableSize / jtm.size;

			if (prospectiveNumEntries > 32) return false;

			ArrayList<Integer> offsets = new ArrayList<>();
			offsets.add(prospectiveTableSize);
			
			for (int i = jtm.size; i < prospectiveTableSize; i += jtm.size) {
				Address nextAddr = jtm.address.getNewAddress(jtm.address.getOffset() + i, true);
				this.createDataAt(api, listing, nextAddr, jtm.dataType, jtm.size);
				offsets.add(this.getBytesAsSignedInteger(listing.getDataAt(nextAddr).getBytes()));
			}
			
			Address computedJumpAddress = computedJump.instruction.getAddress();
			Set<Address> destSet = new HashSet<>();
			for (int i = 0; i < offsets.size(); i++) {
				Address jmpTargetAddress = jtm.address.getNewAddress(jtm.address.getOffset() + offsets.get(i));
				destSet.add(jmpTargetAddress);
				computedJump.instruction.addOperandReference(0, jmpTargetAddress, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED);
			}
			ArrayList<Address> destList = new ArrayList<>(destSet);
			JumpTable jumpTable = new JumpTable(computedJumpAddress, destList, true);
			jumpTable.writeOverride(function);
			CreateFunctionCmd.fixupFunctionBody(program, function, monitor);

			return true;
		} catch (Exception e) {
			return false;
		}
	}
	
	private void createDataAt(FlatProgramAPI api, Listing listing, Address target, DataType dataType, int size) throws Exception {
		Data data = listing.getDataAt(target);
		boolean hasData = data != null && data.getBaseDataType().isEquivalent(dataType);

		if (data != null && !hasData) {
			api.removeDataAt(target);
		}
		if (!hasData) {
			listing.createData(target, dataType, size);
		}
	}
	
	private int getBytesAsUnsignedInteger(byte[] bytes) {
		int result = 0;
		for (int i = 0; i < bytes.length; i++) {
			result = ((result & 0xff) << 8) | (bytes[i] & 0xff);
		}
		return result;
	}
	
	private int getBytesAsSignedInteger(byte[] bytes) {
		int result = 0;
		for (int i = 0; i < bytes.length; i++) {
			result = (result << 8) | bytes[i] & 0xff;
		}
		return result;
	}


	private enum ComputedJumpType {
		INDEXED(),
		DIRECT();
	}

	private class JumpTableMetadata {
		Address address;
		int size;
		DataType dataType;
		ComputedJumpType computedJumpType;

		JumpTableMetadata(Address address, int size, ComputedJumpType computedJumpType) {
			this.address = address;
			this.size = size;
			this.computedJumpType = computedJumpType;
			this.dataType = this.parseDataType(size);
		}
		
		private DataType parseDataType(int dataSize) {
			switch (dataSize) {
				case 1:
					return new ByteDataType();
				case 2:
					return new WordDataType();
				case 4:
					if (this.computedJumpType.equals(ComputedJumpType.INDEXED)) {
						return new LongDataType();
					}
					return new Pointer32DataType();
				default:
					return new WordDataType();
			}
		}
		
	}

}
