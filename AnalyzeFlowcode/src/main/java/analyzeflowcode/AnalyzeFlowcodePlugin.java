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

import analyzeflowcode.graph.FunctionMetricsVisualGraphComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.exception.CancelledException;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = "analyzeflowcode",
	category = PluginCategoryNames.GRAPH,
	shortDescription = "Analyze flow code plugin",
	description = "Analyze flow code plugin"
)
//@formatter:on
public class AnalyzeFlowcodePlugin extends ProgramPlugin {

	private FunctionMetricsVisualGraphComponentProvider provider;
	private DockingAction action;

	public AnalyzeFlowcodePlugin(PluginTool tool) {
		super(tool, true, true);
	}

	private void createActions() {
		this.action = new NavigatableContextAction(this.getName(), this.getName()) {
			@Override
			public void actionPerformed(NavigatableActionContext context) {
				provider.setVisible(true);
			}
		};
		this.action.addToWindowWhen(NavigatableActionContext.class);
		this.action.setMenuBarData(new MenuData(new String[] {
				ToolConstants.MENU_GRAPH, "Flowcode graph"
		}));
		this.action.setDescription("Analyzed flowcode graph");
		this.action.setEnabled(true);
		
		this.getTool().addAction(this.action);		
	}

	@Override
	public void init() {
		super.init();
		
		try {
			this.provider = new FunctionMetricsVisualGraphComponentProvider(tool, getName(), getName(), AnalyzeFlowcodeAnalyzer.GRAPH);
		} catch (CancelledException e) {
			e.printStackTrace();
		} 
		this.createActions();
	}
	
	@Override
	protected void dispose() {
		this.provider.dispose();
	}
}
