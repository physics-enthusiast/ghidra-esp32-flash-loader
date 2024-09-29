package esp32_loader.hardware;

import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;

public class ESP32Chip {

	static class ChipData {
		public String chipModel;
		public String chipSubmodel;
		public String chipProcessor;
		public boolean isApproximation;

		public ChipData(String chipModel, String chipSubmodel, String chipProcessor, boolean isApproximation) {
			this.chipModel = chipModel;
			this.chipSubmodel = chipSubmodel;
			this.chipProcessor = chipProcessor;
			this.isApproximation = isApproximation;
		}
	}
	
	public ChipData chipData;
	public ESP32ChipMappings chipMappings;
	public ESP32ChipPeripherals chipPeripherals;
	public ESP32ChipFunctions chipFunctions;

	static ChipData lookup(short chipID) {
		try {
			String chipModel;
			String chipSubmodel;
			String chipProcessor;
		
			Resourcefile chipDatabase = Application.getModuleDataFile("esp32-chip-data.xml");
		
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document doc = builder.parse(chipDatabase.getInputStream());
	
			Element root = doc.getDocumentElement();
	
			NodeList chipList = root.getElementsByTagName("chip");
			Element chipInfo = (Element) chipList.item(0);
			int prevDiff = chipID;
			for (var x = 0; x < chipList.getLength(); x++) {
				Node chipNode = chipList.item(i);
				Element chipElement = (Element) chipNode;
				int curDiff = Math.abs(Short.parseShort(chipElement.getAttribute("id")) - chipID);
				if (curDiff < prevDiff) {
					chipInfo = chipElement;
					prevDiff = curDiff;
				}
				if (curDiff == 0) {
					break;
				}
			}
			chipModel = (String) chipInfo.getElementsByTagName("model");
			chipSubmodel = (String) chipInfo.getElementsByTagName("submodel");
			chipProcessor = (String) chipInfo.getElementsByTagName("processor");
			isApproximation = (curDiff == 0);
			return new ChipData(chipModel, chipSubmodel, chipProcessor, isApproximation);
		} catch (Exception e) {
			String exceptionTxt = e.toString();
			System.out.println(exceptionTxt);
			return new ChipData("esp32", "esp32", "Xtensa:LE:32:default", true);
		}
	}

	public ESP32Chip(short chipID) {
		chipData = this.lookup(chipID);
		try {
			chipMappings = new ESP32ChipMappings(chipData);
		} catch (Exception e) {
			String exceptionTxt = e.toString();
			System.out.println(exceptionTxt);
			chipMappings = new ESP32ChipMappings();
		}
		try {
			chipPeripherals = new ESP32ChipPeripherals(chipData);
		} catch (Exception e) {
			String exceptionTxt = e.toString();
			System.out.println(exceptionTxt);
			chipPeripherals = new ESP32ChipPeripherals();
		}
		try {
			chipFunctions = new ESP32ChipFunctions(chipData);
		} catch (Exception e) {
			String exceptionTxt = e.toString();
			System.out.println(exceptionTxt);
			chipFunctions = new ESP32ChipFunctions();
		}
	}

	public String getSegmentType(int address) {
		return this.chipMappings.getSegmentType(address);
	}
}
