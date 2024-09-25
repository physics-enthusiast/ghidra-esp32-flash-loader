package esp32_loader.flash;

public class ESP32AppSegment {

	public enum SegmentType {
		ROM, SRAM
	}

	public int PhysicalOffset;
	public int LoadAddress;
	public int Length;
	public byte[] Data;
	public boolean Writeable;
	public boolean Executable;
	public SegmentType type;

	public ESP32AppSegment(int addr, int len, byte[] dat, int Permissions) {
		LoadAddress = addr;
		Length = len;
		Data = dat;
		Writeable = (Permissions & 1) != 0;
		Executable = (Permissions & 2) != 0;
		if (Writeable) {
			type = SegmentType.SRAM;
		} else {
			type = SegmentType.ROM;
		}
	}

	public boolean isRead() {
		return true;
	}

	public boolean isWrite() {
		return this.Writeable;
	}

	public boolean isExecute() {
		return this.Executable;
	}

	public boolean isCodeSegment() {
		return this.isExecute();
	}
}
