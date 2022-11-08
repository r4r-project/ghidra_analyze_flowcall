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
package analyzeflowcode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import analyzeflowcode.functions.utils.FunctionUtils;
import analyzeflowcode.graph.FunctionMetricsVisualEdge;
import analyzeflowcode.graph.FunctionMetricsVisualGraph;
import analyzeflowcode.graph.FunctionMetricsVisualVertex;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.services.GoToService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This analyzer create the flowcode graph with informations
 * on the flowcall.
 */
public class AnalyzeFlowcodeAnalyzer extends AbstractAnalyzer {

	//
	// Configuration
	//
	public static final String NAME       = "Flowcode Analyzer";
	public static final String DESC       = "Flowcode Analyzer create a graph from a function with all called functions recursively.";
	public static final AnalyzerType TYPE = AnalyzerType.FUNCTION_ANALYZER;

	//
	// Options
	//
	public static final String       OPT_REDO      = "Re-do";
	public static final String       OPT_REDO_DESC = "Re-analyze if already done";
	public static final HelpLocation OPT_REDO_HELP = null;
	public static final boolean      OPT_REDO_DEF  = true;
	
	public static final String       OPT_ENTRY      = "Entrypoiny";
	public static final String       OPT_ENTRY_DESC = "Set the root address of flowcode anlysis";
	public static final HelpLocation OPT_ENTRY_HELP = null;
	public static final long         OPT_ENTRY_DEF  = -1;
	
	//
	// Was analyzed ?
	//
	public static FunctionMetricsVisualGraph GRAPH = new FunctionMetricsVisualGraph();
	
	//
	// Instance attributes
	//
	private Options         options;
	private FunctionManager functionManager;
	private FlatProgramAPI  flatApi;
	private TaskMonitor     taskMonitor;
	private MessageLog      log;
	private GoToService     goTo;
	
	public AnalyzeFlowcodeAnalyzer() {
		super(NAME, DESC, TYPE);
		this.setSupportsOneTimeAnalysis(true);
	}

	//
	// Extends AbstractAnalyzer
	//
	
	@Override
	public boolean getDefaultEnablement(Program program) {
		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
		//
		// TODO: Think about pertinent checks
		//
		return true;
	}

	@Override
	public void registerOptions(Options opt, Program program) {
		//
		// TODO: Provide options in regard of the program type
		//		
		this.options = opt;
		this.options.registerOption(OPT_REDO, OPT_REDO_DEF, OPT_REDO_HELP, OPT_REDO_DESC);
		this.options.registerOption(OPT_ENTRY, FunctionUtils.getMain(program), OPT_ENTRY_HELP, OPT_ENTRY_DESC);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		this.functionManager = program.getFunctionManager();
		this.flatApi         = new FlatProgramAPI(program, monitor);
		this.taskMonitor     = monitor;		
		this.log             = log;
		this.goTo            =  AutoAnalysisManager.getAnalysisManager(program)
				                                   .getAnalysisTool()
				                                   .getService(GoToService.class);
		
		this.log.appendMsg("Begin of the analysis flowcode plugin");
		
		try {
			this.handleOptions();
			this.createGraph();
		} catch(CancelledException e) {
			this.log.appendException(e);
		}
		
		this.log.appendMsg("End of the analysis flowcode plugin");
		
		return true;
	}

	//
	// My implementations
	//
	
	/**
	 * This function create the graph
	 * 	 
	 * Exceptions:
	 * 	- CancelledException : If an error occurs
	 */
	private void createGraph() throws CancelledException {
		Function entrypoint = this.getEntrypoint();
		HashMap<String, FunctionMetricsVisualVertex> vertices = new HashMap<>();
		List<FunctionMetricsVisualVertex> toTraverse = new ArrayList<>();
		FunctionMetricsVisualVertex current;
		FunctionMetricsVisualVertex calledVertex;
		
		GRAPH = new FunctionMetricsVisualGraph();
		GRAPH.removeEdges(GRAPH.getEdges());
		GRAPH.removeVertices(GRAPH.getVertices());

		toTraverse.add(new FunctionMetricsVisualVertex(entrypoint, this.goTo));
		
		while(toTraverse.size() != 0) {
			current = this.getVertice(toTraverse.remove(0), vertices, toTraverse);
			
			current.getMetrics().feed(
				current.getMetrics().getFunction(),
				false,
				this.flatApi
			);

			for(Function called: current.getMetrics().getFunction().getCalledFunctions(this.taskMonitor)) {
				calledVertex = this.getVertice(new FunctionMetricsVisualVertex(called, this.goTo), vertices, toTraverse);
				GRAPH.addEdge(new FunctionMetricsVisualEdge(current, calledVertex));
			}
			
		}
	}

	private FunctionMetricsVisualVertex getVertice(FunctionMetricsVisualVertex get,
			HashMap<String, FunctionMetricsVisualVertex> vertices, List<FunctionMetricsVisualVertex> toTraverse) {
		if(vertices.containsKey(get.getMetrics().getName())) {
			return vertices.get(get.getMetrics().getName());
		} 
		vertices.put(get.getMetrics().getName(), get);
		toTraverse.add(get);
		GRAPH.addVertex(get);
		this.propagate(get, get.getMetrics().getFunction());
		return get;
	}

	/**
	 * This function feed all parents of current.
	 */
	private void propagate(FunctionMetricsVisualVertex first, Function called) {
		HashSet<FunctionMetricsVisualVertex> marqued = new HashSet<>();
		List<FunctionMetricsVisualVertex> toTraverse = new ArrayList<>();
		FunctionMetricsVisualVertex current;
		
		toTraverse.add(first);
		
		while(toTraverse.size() != 0) {
			current = toTraverse.remove(0);

			if(marqued.contains(current)) { continue; }
			marqued.add(current);
			
			for(FunctionMetricsVisualVertex f: GRAPH.getPredecessors(current)) {
				f.getMetrics().feed(
					current.getMetrics().getFunction(),
					true,
					this.flatApi
				);
				toTraverse.add(f);
			}
		}
	}

	/**
	 * This function test all options requirements
	 * 	 
	 * Exceptions:
	 * 	- CancelledException : If a requirement is satisfied (or not)
	 */
	private void handleOptions() throws CancelledException {
		this.redo();
	}

	/**
	 * This function test if a re-do is required
	 * 	 
	 * Exceptions:
	 * 	- CancelledException : If re-do is not required
	 */
	private void redo() throws CancelledException {
		if(!options.getBoolean(OPT_REDO, OPT_REDO_DEF)) {
			if(GRAPH != null) {
				throw new CancelledException(String.format("%s is false and graph is setted, so done...", OPT_REDO));
			}
			throw new CancelledException(String.format("%s is true and graph is not setted, so error...", OPT_REDO));
		}
	}

	/**
	 * This function return the entrypoint
	 * 
	 * Exceptions:
	 * 	- CancelledException : If entrypoint not found
	 * 
	 * Return:
	 * 	- The function finded
	 */
	private Function getEntrypoint() throws CancelledException {
		Function f = this.options.isDefaultValue(OPT_ENTRY) 
				? this.functionManager.getFunction(0) 
				: this.functionManager.getFunctionAt(this.flatApi.toAddr(options.getLong(OPT_ENTRY, OPT_ENTRY_DEF)));
		if(f == null) { throw new CancelledException("Entrypoint is null"); }
		return f;
	}
}
