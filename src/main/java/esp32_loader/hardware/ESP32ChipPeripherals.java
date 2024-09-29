package esp32_loader.hardware;

import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.StandAloneDataTypeManager;
import org.w3c.dom.*;
import javax.xml.parsers.*;

public class ESP32ChipPeripherals {

	public class ESP32ChipPeripheral {
		public int baseAddr;
		public String peripheralName;
		public StructureDataType struct;
		public int size;

		public ESP32ChipPeripheral(int baseAddr, String peripheralName, StructureDataType struct, int size) {
			this.baseAddr = baseAddr;
			this.peripheralName = peripheralName;
			this.struct = struct;
			this.size = size;
		}
	}

	public List<ESP32ChipPeripheral> chipPeripheralsList;
	
	private void processPeripheral(Element peripheral) throws Exception {
		String baseAddrString = ((Element) (peripheral.getElementsByTagName("baseAddress").item(0))).getTextContent();
		int baseAddr = Integer.decode(baseAddrString);

		String peripheralName = ((Element) (peripheral.getElementsByTagName("name").item(0))).getTextContent();
		Element addressBlock = (Element) peripheral.getElementsByTagName("addressBlock").item(0);
		int size = Integer.decode(addressBlock.getElementsByTagName("size").item(0).getTextContent());

		StructureDataType struct = new StructureDataType(peripheralName, size);
		StandAloneDataTypeManager tempDTMgr = new StandAloneDataTypeManager(peripheralName);

		NodeList registers = peripheral.getElementsByTagName("register");

		for (var x = 0; x < registers.getLength(); x++) {
			Element register = (Element) registers.item(x);
			String registerName = ((Element) (register.getElementsByTagName("name").item(0))).getTextContent();
			String offsetString = ((Element) (register.getElementsByTagName("addressOffset").item(0))).getTextContent();
			int offsetValue = Integer.decode(offsetString);
			String registerSizeString = ((Element) (register.getElementsByTagName("size").item(0))).getTextContent();
			int registerSizeValue = Integer.decode(registerSizeString) >> 3; // bits to bytes
			// sometimes the SVD file implies that end of a register (offset + registerSizeValue) is greater than the struct
			// size (i.e. part of the register field lies outside of the struct)??
			if (offsetValue + registerSizeValue > size) {
				struct.growStructure​(offsetValue + registerSizeValue - size);
				size = offsetValue + registerSizeValue;
			}
			struct.replaceAtOffset(offsetValue, AbstractIntegerDataType.getUnsignedDataType(registerSizeValue, tempDTMgr),
					       registerSizeValue, registerName, "");
		}
		chipPeripheralsList.add(new ESP32ChipPeripheral(baseAddr, peripheralName, struct, size));
	}

	public ESP32ChipPeripherals(ESP32Chip.ChipData chipData) throws Exception {
		ResourceFile svdFile = Application.getModuleDataFile("svd/svd/" + chipData.chipModel + ".svd");

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();

		Document doc = builder.parse(svdFile.getInputStream());

		Element root = doc.getDocumentElement();

		NodeList peripherals = root.getElementsByTagName("peripheral");
		chipPeripheralsList = new ArrayList<ESP32ChipPeripheral>();
		for (var x = 0; x < peripherals.getLength(); x++) {
			processPeripheral((Element) peripherals.item(x));
		}
	}

	public ESP32ChipPeripherals() { // fallback null initialization
		chipPeripheralsList = new ArrayList<ESP32ChipPeripheral>();
	}
} 
