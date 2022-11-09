package analyzeflowcode.graph;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;

import aQute.bnd.service.Plugin;
import analyzeflowcode.analyzer.FunctionAnalyzer;
import analyzeflowcode.functions.FunctionMetrics;
import ghidra.app.services.GoToService;
import ghidra.graph.viewer.vertex.AbstractVisualVertex;
import ghidra.program.model.listing.Function;

/**
 * This class contain the minimal implementation of a visual vertex
 * 
 * Instance attributes:
 * 	- functionMetrics<FunctionMetrics> : The object containing all functions metrics.
 */
public class FunctionMetricsVisualVertex extends AbstractVisualVertex {

	private FunctionMetrics functionMetrics;
	
	public FunctionMetricsVisualVertex(Function f) {
		this.functionMetrics = new FunctionMetrics(f);
	}
	
	/**
	 * Equality is defined by the just the same functionMetrics
	 * 
	 * Return:
	 * 	- true if functionMetrics are equals else false
	 */
	@Override
	public boolean equals(Object other) {
		if(other == null || other.getClass() != this.getClass()) {
			return false;
		}
		
		return ((FunctionMetricsVisualVertex)other).getMetrics() == this.getMetrics();
	}
	
	public FunctionMetrics getMetrics() { return this.functionMetrics; }
	
	//
	// Extends AbstractVisualVertex
	//
	@Override
	public JComponent getComponent() {
		int counter = 0;
		JPanel temp_panel = new JPanel(new FlowLayout());		
		JPanel panel = new JPanel();
		
		panel.setLayout(new BorderLayout());
		panel.add(new JLabel(this.getMetrics().getName()), BorderLayout.NORTH);
		
		for(FunctionAnalyzer a: this.getMetrics().getAnalyzers()) {
			if(counter == 2) {
				panel.add(temp_panel);
				temp_panel = new JPanel(new FlowLayout());
			}
			counter = (counter+1)%2;
			temp_panel.add(a.getComponent());
		}

		if(counter != 2) { panel.add(temp_panel); }

		return panel;
	}

	@Override
	public void dispose() {
	}

}
