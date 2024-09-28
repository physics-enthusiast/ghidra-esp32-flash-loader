package esp32_loader.hardware;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.Scanner;

import generic.jar.ResourceFile;
import ghidra.framework.Application;

public class ESP32ChipMappings {

	private class ESP32ChipAddressRange {
		public int start;
		public int end;
		public String name;

		public ESP32ChipAddressRange(int start, int end, String name) {
			this.start = start;
			this.end = end;
			this.name = name;
		}
	}

	private List<ESP32ChipAddressRange> chipAddressRangesList;

	private List<ESP32ChipAddressRange> getBasicBounds(String Submodel) throws Exception {
		ResourceFile pyFile = Application.getModuleDataFile("esptool/targets/" + Submodel + ".py");
		Scanner sc = new Scanner(pyFile.getInputStream(), "UTF-8");
		// this is the submodel that the current submodel python class inherits from.
		// hold onto it for now, might need it later if matches cannot be found in the current file
		String s = sc.findWithinHorizon("class " + Submodel.toUpperCase() + "ROM\\((.*?)ROM\\):", 0);
		Pattern p = Pattern.compile("(IROM_MAP_START|IROM_MAP_END|DROM_MAP_START|DROM_MAP_END).*?=.*?0x(.*)");
		int IROM_MAP_START;
		int IROM_MAP_END;
		int DROM_MAP_START;
		int DROM_MAP_END;
		Boolean[] matched = {false, false, false, false};
		while (sc.findWithinHorizon(p,0)) {
			var m = sc.match();
			switch (m.group(1)) {
				case "IROM_MAP_START":
					IROM_MAP_START = Integer.parseInt(m.group(2), 16);
					matched[0] = true;
					break;
				case "IROM_MAP_END":
					IROM_MAP_END = Integer.parseInt(m.group(2), 16);
					matched[1] = true;
					break;
				case "DROM_MAP_START":
					DROM_MAP_START = Integer.parseInt(m.group(2), 16);
					matched[2] = true;
					break;
				case "DROM_MAP_END":
					DROM_MAP_END = Integer.parseInt(m.group(2), 16);
					matched[3] = true;
					break;
			}
		}
		if (Arrays.asList(matched).contains(false)) {
			// recurse to look for those values in the superclass, which is the "s" we
			// saved earlier
			return getBasicBounds(s.toLowerCase());
		} else {
			List<ESP32ChipAddressRange> basicBounds = new ArrayList<ESP32ChipAddressRange>();
			basicBounds.add(new ESP32ChipAddressRange(IROM_MAP_START, IROM_MAP_END, "IROM"));
			basicBounds.add(new ESP32ChipAddressRange(DROM_MAP_START, DROM_MAP_END, "DROM"));
			return basicBounds;
		}
	}

	public ESP32ChipMappings() { // fallback null initialization
		chipAddressRangesList = new ArrayList<ESP32ChipAddressRange>();
	}

	public ESP32ChipMappings(ChipData chipData) throws Exception {
		ResourceFile pyFile = Application.getModuleDataFile("esptool/targets/" + chipData.Submodel + ".py");
		Scanner sc = new Scanner(pyFile.getInputStream(), "UTF-8");
		
		// The MEMORY_MAP is defined in python code as an array of
		// [<start address>, <end address>, "<memory region type>"]
		// We first regex match the whole array of arrays, then regex
		// match each array individually to extract its fields
		String s = sc.findWithinHorizon("MEMORY_MAP = \\[((?:[^\\[\\]]*|\\[[^\\[\\]]*\\])*)\\]", 0);
		// s being null is possible, since MEMORY_MAP is not always defined. In particular, as of the
		// time of writing, esp32h2.py does not define it, and appears to rely on just the IROM and
		// DROM bounds to determine memory address permissions (see the usage and code of getBasicBounds())
		if (s) {
			Pattern p = Pattern.compile("\\[.*?0x(.*?),.*?0x(.*?),.*?\"(.*?)\"\\]");
			Matcher m = p.matcher(s);
			int start;
			int end;
			String name;
			// Reorder the address ranges by storing them into a dictionary then reading them back out,
			// in order to control which range has priority in the event of an overlap
			HashMap<String, List<ESP32ChipAddressRange>> chipAddressRangesDict = new HashMap<>();
			while (m.find()) {
				start = Integer.parseInt(m.group(1), 16);
				end = Integer.parseInt(m.group(2), 16);
				name = m.group(3);
				if (!chipAddressRangesDict.containsKey(name)) {
					chipAddressRangesDict.put(new ArrayList<ESP32ChipAddressRange>());
				}
				chipAddressRangesDict.get(name).add(new ESP32ChipAddressRange(start, end, name));
			}
			chipAddressRangesList = new ArrayList<ESP32ChipAddressRange>();
			// order is more permissions > less permissions ( execute > write > read), then more specific
			// (e.g. "RTC_IRAM") > less specific (e.g. "IRAM")
			String[] typePrecedence = {"RTC_IRAM", "DIRAM_IRAM", "RTC_DATA", "CACHE_PRO", "CACHE_APP",
						   "IRAM", "IROM_MASK", "IROM", "RTC_DRAM", "DIRAM_DRAM","EXTRAM_DATA",
						   "DRAM", "DROM_MASK", "DROM", "MEM_INTERNAL", "MEM_INTERNAL2"};
			for (String name : typePrecedence) {
				if (chipAddressRangesDict.containsKey(name)) {
					for (ESP32ChipAddressRange addressRange : chipAddressRangesDict.get(name)) {
						chipAddressRangesList.add(chipAddressRangesDict.get(name));
					}
				}
			}
		}
		// Add the default IROM and DROM bounds
		for (ESP32ChipAddressRange addressRange : getBasicBounds(chipData.Submodel)) {
			chipAddressRangesList.add(addressRange);
		}
	}

	public String getSegmentType(int address) {
		for (ESP32ChipAddressRange addressRange : chipAddressRangesList) {
			if (address >= addressRange.start && address <= addressRange.end) {
				return addressRange.name;
			}
		}
		return "IRAM"; // i.e. generic RWX
	}
} 
