package esp32_loader.flash;

import esp32_loader.exceptions.UnknownModelException;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;

public class ESP32AppImage {
	public byte SegmentCount;
	public int EntryAddress;
	public boolean HashAppended;
	public short chipID;

	public ArrayList<ESP32AppSegment> Segments = new ArrayList<ESP32AppSegment>();

	public ESP32AppImage(BinaryReader reader) throws IOException, UnknownModelException {
		var magic = reader.readNextByte();
		this.SegmentCount = reader.readNextByte();
		var spiByte = reader.readNextByte(); // SPI Byte
		var spiSize = reader.readNextByte(); // SPI Size
		this.EntryAddress = reader.readNextInt();

		var wpPin = reader.readNextByte(); // WP Pin
		var spiPinDrv = reader.readNextByteArray(3); // SPIPinDrv
		chipID = reader.readNextShort(); // Chip ID
		var minChipRev = reader.readNextByte(); // MinChipRev
		var reserved = reader.readNextByteArray(8); // Reserved
		this.HashAppended = (reader.readNextByte() == 0x01);

		ESP32AppMemory addressSpace = new ESP32AppMemory(chipID);
		for (var x = 0; x < this.SegmentCount; x++) {
			int LoadAddress = reader.readNextInt();
			int Length = reader.readNextInt();
			byte[] Data = reader.readNextByteArray(Length); 
			var seg = addressSpace.getSegment(LoadAddress, Length, Data);
			Segments.add(seg);
		}

		/* get to 16 byte boundary */
		while ((reader.getPointerIndex() + 1) % 0x10 != 0) {
			reader.readNextByte();
		}

		reader.readNextByte(); // checksum byte
		if (HashAppended) {
			reader.readNextByteArray(0x20); // hash
		}
	}
}
