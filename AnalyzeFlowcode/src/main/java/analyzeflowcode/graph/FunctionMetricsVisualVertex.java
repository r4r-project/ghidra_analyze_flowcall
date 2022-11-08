package analyzeflowcode.graph;

import java.awt.FlowLayout;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JPanel;

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
	private GoToService goTo;
	
	public FunctionMetricsVisualVertex(Function f, GoToService goTo) {
		this.functionMetrics = new FunctionMetrics(f);
		this.goTo = goTo;
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
		
		panel.setBorder(BorderFactory.createTitledBorder(this.getMetrics().getName()));
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		temp_panel.setVisible(true);

		for(FunctionAnalyzer a: this.getMetrics().getAnalyzers()) {
			if(counter == 2) {
				panel.add(temp_panel);
				temp_panel = new JPanel(new FlowLayout());
				temp_panel.setVisible(true);
			}
			counter = (counter+1)%2;
			JPanel temp_comp = a.getComponent();
			temp_comp.setVisible(true);
			temp_panel.add(temp_comp);
		}
		panel.setVisible(true);	
		
		panel.addMouseListener(new MouseListener() {
			@Override
			public void mouseClicked(MouseEvent e) {
				goTo.goTo(getMetrics().getFunction().getEntryPoint());
			}

			@Override
			public void mousePressed(MouseEvent e) {}

			@Override
			public void mouseReleased(MouseEvent e) {}

			@Override
			public void mouseEntered(MouseEvent e) {}

			@Override
			public void mouseExited(MouseEvent e) {}
		});
		
		panel.setS
		
		return panel;
	}

	@Override
	public void dispose() {
	}

}
