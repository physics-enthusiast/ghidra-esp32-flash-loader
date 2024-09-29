/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package esp32_loader;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.MatchResult;

import esp32_loader.flash.ESP32Flash;
import esp32_loader.flash.ESP32Partition;
import esp32_loader.flash.ESP32App;
import esp32_loader.hardware.ESP32Chip;
import generic.jar.ResourceFile;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.Application;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class esp32_loaderLoader extends AbstractLibrarySupportLoader {
	ESP32Flash parsedFlash = null;
	ESP32App parsedAppImage = null;

	@Override
	public String getName() {

		// TODO: Name the loader. This name must match the name of the loader in the
		// .opinion
		// files.
		return "ESP32 Flash Image";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// TODO: Examine the bytes in 'provider' to determine if this loader can load
		// it. If it
		// can load it, return the appropriate load specifications.
		BinaryReader reader = new BinaryReader(provider, true);

		/* 2nd stage bootloader is at 0x1000, should start with an 0xE9 byte */
		if (reader.length() > 0x1000) {
			var magic = reader.readByte(0x1000);

			if ((magic & 0xFF) == 0xE9) {
				try {
					/* parse the flash... */
					parsedFlash = new ESP32Flash(reader);
					String arch = ESP32Chip.lookup(parsedFlash.chipID).chipProcessor;
					loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(
							new LanguageID(arch), new CompilerSpecID("default")), true));
				} catch (Exception ex) {
				}
			} else {
				/* maybe they fed us an app image directly */
				if ((reader.readByte(0x00) & 0xFF) == 0xE9) {
					/* App image magic is first byte */
					try {
						parsedAppImage = new ESP32App(reader);
						String arch = parsedAppImage.chip.chipData.chipProcessor;
						loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(
								new LanguageID(arch), new CompilerSpecID("default")), true));
					} catch (Exception ex) {
					}
				}
			}
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {

		FlatProgramAPI api = new FlatProgramAPI(program);
		ESP32App imageToLoad = null;
		if (parsedAppImage != null) {
			imageToLoad = parsedAppImage;
		} else {
			/*
			 * they probably gave us a firmware file, lets load that and get the partition
			 * they selected
			 */
			var partOpt = (String) (options.get(0).getValue());

			ESP32Partition part = parsedFlash.GetPartitionByName(partOpt);
			try {
				imageToLoad = part.ParseAppImage();
			} catch (Exception ex) {
				log.appendException(ex);
				imageToLoad = new ESP32App();
			}
		}

		var chip = imageToLoad.chip;
		log.copyFrom(chip.log);
		var chipData = chip.chipData;
		
		StandAloneDataTypeManager existingDTMgr = new StandAloneDataTypeManager(chipData.chipSubmodel.toUpperCase());
		log.appendMsg(existingDTMgr.getName());
		log.appendMsg(Application.getUserTempDirectory().getAbsolutePath());
		
		if (chipData.isApproximation) {
			log.appendMsg("Warning! Unknown chip ID in firmware image, guessing " + chipData.chipSubmodel);
		}
		var dtm = program.getDataTypeManager();
		var space = program.getAddressFactory().getDefaultAddressSpace();
		var listing = program.getListing();
		var symtbl = program.getSymbolTable();
		try {
			AddressSetPropertyMap codeProp = program.getAddressSetPropertyMap("CodeMap");
			if (codeProp == null) {
				codeProp = program.createAddressSetPropertyMap("CodeMap");
			}

			for (var x = 0; x < imageToLoad.SegmentCount; x++) {
				var curSeg = imageToLoad.Segments.get(x);
				var name = curSeg.Name + "_" + Integer.toHexString(curSeg.LoadAddress);

				var blocks = reserveAddressSpace(program, api.toAddr(curSeg.LoadAddress), curSeg.Length, name, log);
				initializeMemoryBlocks(program, blocks, (byte) 0x0,
						       curSeg.isRead(), curSeg.isWrite(), curSeg.isExecute(), log);
				try {
					program.getMemory().setBytes​(api.toAddr(curSeg.LoadAddress), curSeg.Data);
				} catch (Exception ex) {
					log.appendException(ex);
				}

				/* Mark Instruction blocks as code */
				if (curSeg.isCodeSegment()) {
					codeProp.add(api.toAddr(curSeg.LoadAddress), api.toAddr(curSeg.LoadAddress + curSeg.Length));
				}
			}
			/* set the entry point */
			symtbl.addExternalEntryPoint(api.toAddr(imageToLoad.EntryAddress));
		} catch (Exception ex) {
			log.appendException(ex);
		}

		try {
			for (var peripheral : chip.chipPeripherals.chipPeripheralsList) {
				registerPeripheralBlock(program, api, peripheral.baseAddr, peripheral.baseAddr + peripheral.size - 1,
							peripheral.peripheralName);
				
				var namespace = symtbl.getNamespace("Peripherals", null);
				if (namespace == null) {
					namespace = symtbl.createNameSpace(null, "Peripherals", SourceType.ANALYSIS);
				}

				var addr = space.getAddress(peripheral.baseAddr);
				dtm.addDataType(peripheral.struct, DataTypeConflictHandler.REPLACE_HANDLER);
				listing.createData(addr, peripheral.struct);
				symtbl.createLabel(addr, peripheral.peripheralName, namespace, SourceType.USER_DEFINED);
			}
		} catch (Exception ex) {
			log.appendException(ex);
		}
		try {
			if (chip.chipFunctions.hasFunctions) {
				var start = api.toAddr(chip.chipFunctions.minAddr);
				var end = api.toAddr(chip.chipFunctions.maxAddr);
				reserveAddressSpace(program, start, end.subtract(start), "ROM", log);
				for (var struct : chip.chipFunctions.structs) {
					dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
				}
				for (var function : chip.chipFunctions.chipFunctionsList) {
					try {
						var name = function.name;
						var address = api.toAddr(function.address);
						dtm.addDataType(function.definition, DataTypeConflictHandler.REPLACE_HANDLER);
						var existingFunction = api.getFunctionAt(address);
						if (existingFunction != null) {
							var oldName = existingFunction.getName();
							existingFunction.setName(name, SourceType.DEFAULT);
							log.appendMsg(String.format("Renamed function %s to %s at address %s",
										    oldName, name, address));
						} else {
							api.createFunction(address, function.name);
						}
					} catch (Exception ex) {
						log.appendException(ex);
						log.appendMsg("Caused by function: " + function.name);
						continue;
					}
				}
			} else {
				log.appendMsg("Warning! No functions found!");
			}
		} catch (Exception ex) {
			log.appendException(ex);
		}

		// TODO: Load the bytes from 'provider' into the 'program'.

	}

	private List<MemoryBlock> reserveAddressSpace(Program program, Address start, long length, String name, MessageLog log) {
		List<MemoryBlock> blocks = new ArrayList<MemoryBlock>();
		var mem = program.getMemory();
		AddressSet targetSet = new AddressSet(start, start.add(length));
		AddressSet originalSet = mem.intersect(targetSet);
		AddressSet newSet = originalSet.xor(targetSet);
		for (AddressRange newRange : newSet) {
			try {
				MemoryBlock block = mem.createUninitializedBlock​(name, newRange.getMinAddress(),
										 newRange.getLength(), false);
			} catch (Exception ex) {
				log.appendException(ex);
			}
		}
		for (MemoryBlock block : mem.getBlocks()) {
			Address blockStart = block.getStart();
			Address blockEnd = block.getEnd();
			if (targetSet.intersects(blockStart, blockEnd)) {
				blocks.add(block);
			}
		}
		return blocks;
	}

	private void initializeMemoryBlocks(Program program, List<MemoryBlock> blocks, byte initialValue,
					    boolean read, boolean write, boolean execute, MessageLog log) {
		for (MemoryBlock block : blocks) {
			if (!block.isInitialized()) {
				try {
					program.getMemory().convertToInitialized(block, initialValue);
				} catch (Exception ex) {
					log.appendException(ex);
				}
				block.setPermissions(read, write, execute);
			}
		}
	}

	private void registerPeripheralBlock(Program program, FlatProgramAPI api, int startAddr, int endAddr, String name)
			throws LockException, DuplicateNameException, MemoryConflictException, AddressOverflowException {
		// TODO Auto-generated method stub
		var block = program.getMemory().createUninitializedBlock(name, api.toAddr(startAddr), endAddr - startAddr + 1,
				false);
		block.setRead(true);
		block.setWrite(true);
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = new ArrayList<Option>();

		if (parsedFlash != null) {
			// TODO: If this loader has custom options, add them to 'list'
			list.add(new PartitionOption(parsedFlash));
		}
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here. Not all options
		// require
		// validation.
		if (options.get(0).getValue() == null || options.get(0).getValue().equals("")) {
			return "App partition not found in image.";
		}
		return null;
		// return super.validateOptions(provider, loadSpec, options, program);
	}
}
