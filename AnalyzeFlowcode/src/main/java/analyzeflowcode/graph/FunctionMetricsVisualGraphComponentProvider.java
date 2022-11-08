package analyzeflowcode.graph;

import java.awt.BorderLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;

import analyzeflowcode.graph.layouts.FunctionMetricsGraphLayoutProvider;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.VisualGraphComponentProvider;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

public class FunctionMetricsVisualGraphComponentProvider extends ComponentProviderAdapter {

	private VisualGraphView<
		FunctionMetricsVisualVertex, 
		FunctionMetricsVisualEdge, 
		FunctionMetricsVisualGraph
	> graphView;
	private FunctionMetricsGraphLayoutProvider layoutProvider;
	private FunctionMetricsVisualGraph graph;
	
	public FunctionMetricsVisualGraphComponentProvider(PluginTool tool, String name, String owner, FunctionMetricsVisualGraph graph) throws CancelledException {
		super(tool, name, owner);

		this.addToTool();

		this.graph          = graph;
		this.layoutProvider = new FunctionMetricsGraphLayoutProvider();
		this.graphView = new VisualGraphView<>();
	}

	@Override
	public JComponent getComponent() {
		// TODO: View if tooltips are utils (VertexTooltipProvider)
		// https://github.com/NationalSecurityAgency/ghidra/blob/69b07161bb1111c33bccedcf1dc8f54ed37db310/Ghidra/Extensions/sample/src/main/java/ghidra/examples/graph/SampleGraphProvider.java#L114
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(this.graphView.getViewComponent());
		return panel;
	}

	@Override
	public void componentShown() {
		this.installGraph();
	}
	
	private void installGraph() {
		if(this.graph != null) { this.graph.dispose(); }

		try {
			this.graph.setLayout(this.layoutProvider.getLayout(this.graph, null));
		} catch (CancelledException e) {}
		
		this.graphView.setLayoutProvider(this.layoutProvider);
		this.graphView.setGraph(this.graph);
	}
	
	public void dispose() {
		this.removeFromTool();
	}
}
