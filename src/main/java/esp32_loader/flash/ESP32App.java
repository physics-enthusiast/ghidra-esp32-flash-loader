package esp32_loader.flash;

import esp32_loader.hardware.ESP32Chip;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;

public class ESP32App {
	public byte SegmentCount;
	public int EntryAddress;
	public boolean HashAppended;
	public short chipID;
	public ESP32Chip chip;

	public class ESP32AppSegment {
		public int PhysicalOffset;
		public int LoadAddress;
		public int Length;
		public byte[] Data;
		public boolean Readable;
		public boolean Writeable;
		public boolean Executable;
		public String Name;
	
		public ESP32AppSegment(int LoadAddress, int Length, byte[] Data, String Name) {
			this.LoadAddress = LoadAddress;
			this.Length = Length;
			this.Data = Data;
			this.Name = Name;
			switch (Name) {
				// RWX
				case "RTC_IRAM":
				case "DIRAM_IRAM":
				case "RTC_DATA":
				case "CACHE_PRO":
				case "CACHE_APP":
				case "IRAM":
					Readable = true;
					Writeable = true;
					Executable = true;
					break;
				// RX
				case "IROM_MASK":
				case "IROM":
					Readable = true;
					Writeable = false;
					Executable = true;
					break;
				// RW
				case "RTC_DRAM":
				case "DIRAM_DRAM":
				case "EXTRAM_DATA":
				case "DRAM":
					Readable = true;
					Writeable = true;
					Executable = false;
					break;
				// R
				case "DROM_MASK":
				case "DROM":
					Readable = true;
					Writeable = false;
					Executable = false;
					break;
				// NONE
				case "MEM_INTERNAL":
				case "MEM_INTERNAL2":
					Readable = false;
					Writeable = false;
					Executable = false;
					break;
				default: // Shouldn't happen, but just in case
					Readable = true;
					Writeable = true;
					Executable = true;
					break;
			}
		}
	
		public boolean isRead() {
			return this.Readable;
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

	public ArrayList<ESP32AppSegment> Segments = new ArrayList<ESP32AppSegment>();

	public ESP32App(BinaryReader reader) throws IOException {
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

		chip = new ESP32Chip(chipID);
		for (var x = 0; x < this.SegmentCount; x++) {
			int LoadAddress = reader.readNextInt();
			int Length = reader.readNextInt();
			byte[] Data = reader.readNextByteArray(Length); 
			String Name = chip.chipMappings.getSegmentType(LoadAddress);
			Segments.add(new ESP32AppSegment(LoadAddress, Length, Data, Name));
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

	public ESP32App() { // fallback null initialization
		SegmentCount = 0;
		EntryAddress = 0;
		HashAppended = false;
		chipID = 0;
		chip = new ESP32Chip((short) 0);
	}
}
