package esp32_loader.hardware;

import java.lang.Math
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;

public class ESP32Chip {

	public class ChipData {
		public String chipModel;
		public String chipSubmodel;
		public String chipProcessor;
	}
	
	public ChipData chipData;
	public boolean isApproximation;

	public ESP32Chip(short chipID) {
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
			int diff = chipID;
			for (var x = 0; x < chipList.getLength(); x++) {
				Node chipNode = chipList.item(i);
				Element chipElement = (Element) chipNode;
				int newDiff = Math.abs(short.valueOf(chipElement.getAttribute("id")) - chipID);
				if (newDiff < diff) {
					chipInfo = chipElement;
					diff = newDiff;
				}
				if (newDiff == 0) {
					break;
				}
			}
			chipModel = (String) chipInfo.getElementsByTagName("model");
			chipSubmodel = (String) chipInfo.getElementsByTagName("submodel");
			chipProcessor = (String) chipInfo.getElementsByTagName("processor");
			chipData = new ChipData(chipModel, chipSubmodel, chipProcessor);
			isApproximation = (newDiff == 0);
		} catch (Exception e) {
			String exceptionTxt = e.toString();
			System.out.println(exceptionTxt);
			chipData = new ChipData("esp32", "esp32", "Xtensa:LE:32:default");
			isApproximation = true;
		}
	}
}
