package mbdesu.cps2.util;

import ghidra.program.model.listing.Instruction;

public class InstructionWrapper {
	
	public Instruction instruction;

	public InstructionWrapper(Instruction instruction) {
		this.instruction = instruction;
	}
	
	@Override
	public String toString() {
		String instructionAddress = instruction.getAddressString(true, true);
		String instructionMnemonic = instruction.getMnemonicString();
		StringBuilder instructionStringBuilder = new StringBuilder().append(instructionAddress).append(": ").append(instructionMnemonic).append(' ');
		int numOperands = instruction.getNumOperands();
		
		for (int i = 0; i < numOperands; i++) {
			instructionStringBuilder.append(instruction.getDefaultOperandRepresentation(i));
			if (i < numOperands - 1) instructionStringBuilder.append(',');
		}

		return instructionStringBuilder.toString();
	}
	
	public InstructionWrapper getPrevious() {
		return new InstructionWrapper(this.instruction.getPrevious());
	}
	
	public boolean isComputedJump() {
		return this.instruction != null && this.instruction.getFlowType().isComputed();
	}
	
	public boolean isMove() {
		return this.instruction != null && this.instruction.getMnemonicString().startsWith("move");
	}
	
	public int getJumpTableSize() {
		if (this.instruction != null && this.isMove()) {
			switch (this.instruction.getMnemonicString()) {
				case "movea.l":
				case "move.l":
					return 4;
				case "move.b":
					return 1;
				case "move.w":
				default:
					return 2;
			}
		}
		return -1;
	}
	
}
