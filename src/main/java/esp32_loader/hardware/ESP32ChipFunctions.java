package esp32_loader.hardware;

import java.io.File;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.util.task.TaskMonitor;

public class ESP32ChipFunctions {

	public class ESP32ChipFunction {
		public String name;
		public int address;
		public FunctionDefinition definition;

		public ESP32ChipFunction(String name, int address, FunctionDefinition definition) {
			this.name = name;
			this.address = address;
			this.definition = definition;
		}
	}

	private List<String> findExtensionRecursive(Resourcefile rootdir, String ext) {
		List<String> filenameList = new ArrayList<String>();
		for (ResourceFile fileOrFolder : rootDir.listFiles()) {
			String rootName = fileOrFolder.getName();
			if (fileOrFolder.isFile()) {
				if ( rootName.substring(Math.max(rootName.length() - ext.length(), 0)) == ext) {
					filenameList.add(rootName);
				}
			} else if (fileOrFolder.isDirectory()) {
				for (String branchName : findExtensionRecursive(fileOrFolder)) {
					filenameList.add(rootName + "/" + branchName);
				}
			}
		}
		return filenameList
	}

	public List<ESP32ChipFunction> chipFunctionsList;
	public List<Structure> structs;
	public int minAddr;
	public int maxAddr;
	public boolean hasFunctions = false;

	public ESP32ChipFunctions(ESP32Chip.ChipData chipData) throws Exception {
		String romDir = "esp-idf/components/esp_rom";
		String romSubmodelDir = romDir + "/" + chipData.chipSubmodel;
		String romSubmodelIncludeDir = romSubmodelDir + "/include/" + chipData.chipSubmodel;
		// from include_dirs of esp-idf/components/esp_rom/CMakeLists.txt
		ResourceFile[] includeDirs = {Application.getModuleDataSubDirectory(romDir + "/include"),
					      Application.getModuleDataSubDirectory(romSubmodelDir),
					      Application.getModuleDataSubDirectory(romSubmodelDir + "/include"),
					      Application.getModuleDataSubDirectory(romSubmodelIncludeDir)};
		List<String> filenameList = new ArrayList<String>();
		List<String> includePathList = new ArrayList<String>();
		List<String> argList = new ArrayList<String>();
		for (ResourceFile includeDir : includeDirs) {
			for (String name : findExtensionRecursive(includeDir, ".h")) {
				if (!filenameList.contains(name)) {
					filenameList.add(name);
				}
			}
			includePathList.add(includeDir.getAbsolutePath());
			argList.add("-I" + includeDir.getAbsolutePath());
		}
		String[] filenames = new String[filenameList.size()];
		filenameList.toArray(filenames);
		String[] includePaths = new String[includePathList.size()];
		includePathList.toArray(includePaths);
		String[] args = new String[argList.size()];
		argList.toArray(args);
		File f = new File(Application.getUserTempDirectory(), "esp32_tmp.gdt");
		String path = f.getAbsolutePath();
		if (f.exists()) {
			f.delete();
		}
		String lockFile = path + ".ulock";
		File lf = new File(lockFile);
		if (lf.exists()) {
			lf.delete();
		}
		
		FileDataTypeManager existingDTMgr = FileDataTypeManager.createFileArchive(f);
		CParserUtils.parseHeaderFiles(new FileDataTypeManager[0], filenames, includePaths, args,
					      existingDTMgr, chipData.chipProcessor, "default", TaskMonitor.DUMMY);
		structs = new ArrayList<Structure>();
		Iterator<Structure> structIter = existingDTMgr.getAllStructures();
		while (structIter.hasNext()) {
			Structure struct = structIter.next();
			structs.add(struct);
		}
		HashMap<String, FunctionDefinition> chipFunctionsDict = new HashMap<>();
		Iterator<FunctionDefinition> funcIter = existingDTMgr.getAllFunctionDefinitions();
		while (funcIter.hasNext()) {
			FunctionDefinition functionDefinition = funcIter.next();
			chipFunctionsDict.put(functionDefinition.getName(), functionDefinition);
		}
		ResourceFile ldFileDir = Application.getModuleDataSubDirectory(romSubmodelDir + "/ld");
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
				var m = sc.match();
				String name = m.group(1).trim();
				try {
					int address = Integer.parseInt(m.group(2).trim(), 16);
					chipFunctionsList.add(new ESP32ChipFunction(name, address, chipFunctionsDict.get(name)));
					if (hasFunctions) {
						minAddr = Math.min(minAddr, address);
						maxAddr = Math.max(maxAddr, address);
					} else {
						minAddr = address;
						maxAddr = address;
						hasFunctions = true;
					}
				} catch(NumberFormatException e) {
				}
			}
		}
	}

	public ESP32ChipFunctions() { // fallback null initialization
		chipFunctionsList = new ArrayList<ESP32ChipFunction>();
		structs = new ArrayList<Structure>();
	}
} 
