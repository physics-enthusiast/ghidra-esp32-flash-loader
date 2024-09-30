package esp32_loader.hardware;

import java.util.*;

import generic.jar.ResourceFile;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import org.w3c.dom.*;
import javax.xml.parsers.*;

public class ESP32Chip {

	public static class ChipData {
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

	public MessageLog log = new MessageLog();
	public ChipData chipData;
	public ESP32ChipMappings chipMappings;
	public ESP32ChipPeripherals chipPeripherals;
	public ESP32ChipFunctions chipFunctions;

	public static ChipData lookup(short chipID, MessageLog log) {
		try {
			String chipModel;
			String chipSubmodel;
			String chipProcessor;
		
			ResourceFile chipDatabase = Application.getModuleDataFile("esp32-chip-data.xml");
		
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document doc = builder.parse(chipDatabase.getInputStream());
	
			Element root = doc.getDocumentElement();
	
			NodeList chipList = root.getElementsByTagName("chip");
			Element chipInfo = (Element) chipList.item(0);
			int prevDiff = chipID;
			for (var x = 0; x < chipList.getLength(); x++) {
				Node chipNode = chipList.item(x);
				Element chipElement = (Element) chipNode;
				int curDiff = Math.abs(Short.parseShort(chipElement.getAttribute("id")) - chipID);
				if (curDiff < prevDiff) {
					chipInfo = chipElement;
					prevDiff = curDiff;
				}
				if (curDiff == 0) {
					prevDiff = curDiff;
					break;
				}
			}
			chipModel = chipInfo.getElementsByTagName("model").item(0).getTextContent();
			chipSubmodel = chipInfo.getElementsByTagName("submodel").item(0).getTextContent();
			chipProcessor = chipInfo.getElementsByTagName("processor").item(0).getTextContent();
			boolean isApproximation = (prevDiff != 0);
			return new ChipData(chipModel, chipSubmodel, chipProcessor, isApproximation);
		} catch (Exception e) {
			log.appendException(e);
			return new ChipData("esp32", "esp32", "Xtensa:LE:32:default", true);
		}
	}

	public static ChipData lookup(short chipID) {
		return lookup(chipID, new MessageLog());
	}

	public ESP32Chip(short chipID) {
		chipData = this.lookup(chipID, log);
		try {
			chipMappings = new ESP32ChipMappings(chipData);
		} catch (Exception e) {
			log.appendException(e);
			chipMappings = new ESP32ChipMappings();
		}
		try {
			chipPeripherals = new ESP32ChipPeripherals(chipData);
		} catch (Exception e) {
			log.appendException(e);
			chipPeripherals = new ESP32ChipPeripherals();
		}
		try {
			chipFunctions = new ESP32ChipFunctions(chipData);
		} catch (Exception e) {
			log.appendException(e);
			chipFunctions = new ESP32ChipFunctions();
		}
	}
}
