package analyzeflowcode.graph;

import java.awt.BorderLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;

import analyzeflowcode.AnalyzeFlowcodePlugin;
import analyzeflowcode.graph.layouts.FunctionMetricsGraphLayoutProvider;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.graph.viewer.event.mouse.VertexMouseInfo;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.graph.viewer.vertex.VertexClickListener;
import ghidra.graph.viewer.vertex.VertexFocusListener;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FunctionMetricsVisualGraphComponentProvider extends ComponentProviderAdapter {

	private VisualGraphView<
		FunctionMetricsVisualVertex, 
		FunctionMetricsVisualEdge, 
		FunctionMetricsVisualGraph
	> graphView;
	private FunctionMetricsGraphLayoutProvider layoutProvider;
	private FunctionMetricsVisualGraph graph;
	private AnalyzeFlowcodePlugin plugin;
	private JComponent mainPanel;
	private VisualGraphView<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge, FunctionMetricsVisualGraph> view;
	private JComponent component;
	
	public FunctionMetricsVisualGraphComponentProvider(PluginTool tool, AnalyzeFlowcodePlugin plugin) {
		super(tool, plugin.getName(), plugin.getName());
		this.plugin = plugin;
		this.layoutProvider = new FunctionMetricsGraphLayoutProvider();
		addToTool();
		buildComponent();
	}

	private void installGraph() {
		buildGraph();

		this.view.setLayoutProvider(layoutProvider);
		this.view.setGraph(graph);
	}

	public void dispose() {
		removeFromTool();
	}

	@Override
	public void componentShown() {
		installGraph();
	}

	private void buildComponent() {
		this.view = new VisualGraphView<>();
		this.view.setVertexFocusListener(new VertexFocusListener<FunctionMetricsVisualVertex>() {

			@Override
			public void vertexFocused(FunctionMetricsVisualVertex v) {
				plugin.exposedGoTo(v.getMetrics().getFunction().getEntryPoint());
			}
			
		});
		this.component = this.view.getViewComponent();
		this.mainPanel = new JPanel(new BorderLayout());
		this.mainPanel.add(this.component, BorderLayout.CENTER);
	}

	private void buildGraph() {
		graph = this.plugin.createGraph();

		try {
			VisualGraphLayout<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> layout =
				layoutProvider.getLayout(graph, TaskMonitor.DUMMY);
			graph.setLayout(layout);
		}
		catch (CancelledException e) {
			// can't happen as long as we are using the dummy monitor
		}
	}

	public FunctionMetricsVisualGraph getGraph() {
		return graph;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}
}
