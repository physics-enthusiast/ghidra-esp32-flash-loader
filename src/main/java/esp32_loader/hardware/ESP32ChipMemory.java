package esp32_loader.hardware;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.Scanner;

import ghidra.framework.Application;

public class ESP32ChipMemory {

	public ESP32ChipMemory(ChipData chipData) throws Exception {
		pyFile = Application.getModuleDataFile("esptool/targets/" + chipData.Submodel + ".py");
		Scanner sc = new Scanner(pyFile.getInputStream(), "UTF-8");
		// The MEMORY_MAP is defined in python code as an array of
		// [<start address>, <end address>, "<memory region type>"]
		// We first regex match the whole array of arrays, then regex
		// match each array individually to extract its fields
		String s = sc.findWithinHorizon("MEMORY_MAP = \\[((?:[^\\[\\]]*|\\[[^\\[\\]]*\\])*)\\]", 0);
		Pattern p = Pattern.compile("\\[.*?0x(.*?),.*?0x(.*?),.*?\"(.*?)\"\\]");
		Matcher m = p.matcher(s);
		int start;
		int end;
		String name;
		while (m.find()) {
			start = Integer.parseInt(m.group(1), 16);
			start = Integer.parseInt(m.group(2), 16);
			name = m.group(3);
		}		
	}
} 
