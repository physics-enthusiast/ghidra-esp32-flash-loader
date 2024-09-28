package esp32_loader.hardware;

import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedLongDataType;

public class ESP32ChipFunctions {

	public class ESP32ChipFunction {
		public String name;
		public int address;

		public ESP32ChipFunction(String name, int address) {
			this.name = name;
			this.address = address;
		}
	}

	public List<ESP32ChipFunction> chipFunctionsList;

	public ESP32ChipFunctions(ChipData chipData) throws Exception {
		ResourceFile ldFileDir = Application.getModuleDataFile("esp-idf/components/esp_rom/" + chipData.Model + "/ld");
		ResourceFile[] ldFileList = ldFileDir.listFiles();

		chipFunctionsList = new ArrayList<ESP32ChipFunction>();
		for (ResourceFile ldFile : ldFileList) {
			Scanner sc = new Scanner(ldFile.getInputStream(), "UTF-8");
			// Match the 2 kinds of .ld patterns:
			// 1. <symbol name> = <address>;
			// 2. PROVIDE ( <symbol name> = <address> );
			// in such a way that the "PROVIDE"s, brackets, equal signs, and semicolons are removed
			Pattern p = Pattern.compile("(?:PROVIDE \\( |)(.*)=(.*?)(?:\\)|);");
			while (sc.findWithinHorizon(p, 0) != null) {
				MatchResult m = sc.match();
				String name = m.group(1).trim();
				int address = Integer.parseInt(m.group(2).trim(), 16);
				chipFunctionsList.add(new ESP32ChipFunction(name, address));
			}
		}
	}

	public ESP32ChipFunctions() { // fallback null initialization
		chipFunctionsList = new ArrayList<ESP32ChipFunction>();
	}
} 
