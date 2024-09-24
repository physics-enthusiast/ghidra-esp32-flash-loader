package esp32_loader.flash;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

public class UnknownModelException extends Exception { 
    public UnknownModelException(String errorMessage) {
        super(errorMessage);
    }
}

public class ESP32AddressRange {
	public int StartAddress;
	public int EndAddress;
	public boolean Writeable;
	public boolean Executable;
}

public class ESP32AddressSpace {
	private List<ESP32AddressRange> ESP32AddressRangeList = new ArrayList<ESP32AddressRange>();
	private void SetAddressRangePermissions(int StartAddress, int EndAddress, boolean Writeable, boolean Executable) {
		ESP32AddressRangeList.add(new ESP32AddressRange(StartAddress, EndAddress, Writeable, Executable));
	}
	public ESP32AddressSpace(short chipID) throws UnknownModelException {
		switch(chipID) { // based on the technical reference manuals of the respective chips
			case 0: // ESP32
				// internal
				this.SetAddressRangePermissions(0x3FF9_0000, 0x3FF9_FFFF, false, false);
				this.SetAddressRangePermissions(0x3FFA_E000, 0x3FFD_FFFF, true, false);
				this.SetAddressRangePermissions(0x3FFE_0000, 0x3FFF_FFFF, true, false);
				this.SetAddressRangePermissions(0x4000_0000, 0x4000_7FFF, false, true);
				this.SetAddressRangePermissions(0x4000_8000, 0x4005_FFFF, false, true);
				this.SetAddressRangePermissions(0x4007_0000, 0x4007_FFFF, true, true);
				this.SetAddressRangePermissions(0x4008_0000, 0x4009_FFFF, true, true);
				this.SetAddressRangePermissions(0x400A_0000, 0x400A_FFFF, true, true);
				this.SetAddressRangePermissions(0x400B_0000, 0x400B_7FFF  true, true);
				this.SetAddressRangePermissions(0x400B_8000, 0x400B_FFFF, true, true);
				// external
				this.SetAddressRangePermissions(0x3F40_0000, 0x3F7F_FFFF, false, false);
				this.SetAddressRangePermissions(0x3F80_0000, 0x3FBF_FFFF, true, false);
				this.SetAddressRangePermissions(0x400C_2000, 0x40BF_FFFF, true, true);
				break
			case 2: // ESP32-S2
				// internal
				this.SetAddressRangePermissions(0x3FFA_0000, 0x3FFA_FFFF, false, false);
				this.SetAddressRangePermissions(0x3FFB_0000, 0x3FFB_7FFF, true, false);
				this.SetAddressRangePermissions(0x3FFB_8000, 0x3FFF_FFFF, true, false);
				this.SetAddressRangePermissions(0x4000_0000, 0x4000_FFFF, false, true);
				this.SetAddressRangePermissions(0x4001_0000, 0x4001_FFFF, false, true);
				this.SetAddressRangePermissions(0x4002_0000, 0x4002_7FFF, true, true);
				this.SetAddressRangePermissions(0x4002_8000, 0x4006_FFFF, true, true);
				// external
				this.SetAddressRangePermissions(0x3F00_0000, 0x3F3F_FFFF, true, false);
				this.SetAddressRangePermissions(0x3F50_0000, 0x3FF7_FFFF, true, false);
				this.SetAddressRangePermissions(0x4008_0000, 0x407F_FFFF, true, true);
				break
			case 9: // ESP32-S3
				// internal
				this.SetAddressRangePermissions(0x3FF0_0000, 0x3FF1_FFFF, false, false);
				this.SetAddressRangePermissions(0x3FC8_8000, 0x3FCE_FFFF, true, false);
				this.SetAddressRangePermissions(0x3FCF_0000, 0x3FCF_FFFF, true, false);
				this.SetAddressRangePermissions(0x4000_0000, 0x4003_FFFF, false, true);
				this.SetAddressRangePermissions(0x4004_0000, 0x4005_FFFF, false, true);
				this.SetAddressRangePermissions(0x4037_0000, 0x4037_7FFF, true, true);
				this.SetAddressRangePermissions(0x4037_8000, 0x403D_FFFF, true, true);
				// external
				this.SetAddressRangePermissions(0x3C00_0000, 0x3DFF_FFFF, true, false);
				this.SetAddressRangePermissions(0x4200_0000, 0x43FF_FFFF, true, true);
				break
			case 12: // ESP32-C2
				// internal
				this.SetAddressRangePermissions(0x3FF0_0000, 0x3FF4_FFFF, false, false);
				this.SetAddressRangePermissions(0x3FCA_0000, 0x3FCD_FFFF, true, false);
				this.SetAddressRangePermissions(0x4000_0000, 0x4003_FFFF, false, true);
				this.SetAddressRangePermissions(0x4004_0000, 0x4008_FFFF, false, true);
				this.SetAddressRangePermissions(0x4037_C000, 0x4037_FFFF, true, true);
				this.SetAddressRangePermissions(0x4038_0000, 0x403B_FFFF, true, true);
				// external
				this.SetAddressRangePermissions(0x3C00_0000, 0x3C3F_FFFF, false, false);
				this.SetAddressRangePermissions(0x4200_0000, 0x423F_FFFF, true, true);
				break
			case 5: // ESP32-C3
				// internal
				this.SetAddressRangePermissions(0x3FF0_0000, 0x3FF1_FFFF, false, false);
				this.SetAddressRangePermissions(0x3FC8_0000, 0x3FCD_FFFF, true, false);
				this.SetAddressRangePermissions(0x4000_0000, 0x4003_FFFF, false, true);
				this.SetAddressRangePermissions(0x4004_0000, 0x4005_FFFF, false, true);
				this.SetAddressRangePermissions(0x4037_C000, 0x4037_FFFF, true, true);
				this.SetAddressRangePermissions(0x4038_0000, 0x403D_FFFF, true, true);
				// external
				this.SetAddressRangePermissions(0x3C00_0000, 0x3C7F_FFFF, false, false);
				this.SetAddressRangePermissions(0x4200_0000, 0x427F_FFFF, true, true);
				break
			case 13: // ESP32-C6
			case 20:
				// internal
				this.SetAddressRangePermissions(0x4000_0000, 0x4004_FFFF, false, true);
				this.SetAddressRangePermissions(0x4080_0000, 0x4087_FFFF, true, true);
				this.SetAddressRangePermissions(0x5000_0000, 0x5000_3FFF, true, true);
				// external
				this.SetAddressRangePermissions(0x4200_0000, 0x42FF_FFFF, true, true);
				break
			case 16: // ESP32-H2
				// internal
				this.SetAddressRangePermissions(0x4000_0000, 0x4001_FFFF, false, true);
				this.SetAddressRangePermissions(0x4080_0000, 0x4084_FFFF, true, true);
				this.SetAddressRangePermissions(0x5000_0000, 0x5000_0FFF, true, true);
				// external
				this.SetAddressRangePermissions(0x4200_0000, 0x42FF_FFFF, true, true);
			default:
				throw new UnknownModelException("Unknown ESP32 Chip ID : " + chipID );
		}
	}
	private int GetAddressRangePermissions(int address) {
		private boolean addressRangeFound = false;
		private boolean addressRangeWriteable = false;
		private boolean addressRangeExecutable = false;
		for (ESP32AddressRange addressRange : ESP32AddressRangeList) {
			if (address >= addressRange.StartAddress && address <= addressRange.EndAddress) {
				addressRangeWriteable = addressRange.Writeable;
				addressRangeExecutable = addressRange.Executable;
				break
			}
		}
		if (!addressRangeFound) {
			addressRangeWriteable = true;
			addressRangeExecutable = true;
		}
		return (addressRangeWriteable ? 1 : 0) + (addressRangeExecutable ? 2 : 0);
	}
}

public class ESP32AppSegment {

	public int PhysicalOffset;
	public int LoadAddress;
	public int Length;
	public byte[] Data;
	public int Permissions;

	public ESP32AppSegment(ESP32AppImage app, BinaryReader reader, ESP32AddressSpace addressSpace) throws IOException {
		LoadAddress = reader.readNextInt();
		Length = reader.readNextInt();
		Data = reader.readNextByteArray(Length);
		Permissions = addressSpace.GetAddressRangePermissions(LoadAddress);
	}

	public boolean isRead() {
		return true;
	}

	public boolean isWrite() {
		return ((this.Permissions & 1) != 0);
	}

	public boolean isExecute() {
		return ((this.Permissions & 1) != 0);
	}

	public boolean isCodeSegment() {
		return this.isExecute();
	}
}
