// Create a recursive callgraph from current function in dot format
//@author Javier Yuste
//@category Graphs
//@keybinding 
//@menupath 
//@toolbar 

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class DeepGraph extends GhidraScript {
	
	private ArrayList<Function> nodesList;
	private ArrayList<Function> visitedNodesList;
	private String dotGraph;
	private FileWriter fileWriter;
	private File dotFile;
	private List<String> dotLines;

    public void run() throws Exception {
    	try
    	{
    		this.nodesList = new ArrayList<Function> ();
    		this.visitedNodesList = new ArrayList<Function> ();
    		Function currentFunction = getFunctionContaining(currentAddress);
        	if (currentFunction == null)
        	{
        		currentFunction = askForFunction();
        	}
        	this.initiateDotFile(currentFunction.getName());
			this.addNode(currentFunction);
        	recursiveRefsFetch(currentFunction);
        	this.writeToFile();
    	}
    	catch (Exception e)
    	{
    		throw e;
    	}
    }
    
    private void recursiveRefsFetch(Function currentFunction) throws Exception {
    	try 
    	{
    		println("Entering with " + currentFunction.getName());
    		// Mark this function as visited
    		if (!this.visitedNodesList.contains(currentFunction))
    		{
    			this.visitedNodesList.add(currentFunction);
        		// Get references from currentFunction
    			Set<Function> callingFunctions = currentFunction.getCalledFunctions(new TaskMonitorAdapter());
    			Iterator<Function> callingFunctionsIter = callingFunctions.iterator();
    			while(callingFunctionsIter.hasNext())
    			{
    				Function currentCallingFunction = callingFunctionsIter.next();
    				this.addNode(currentCallingFunction);
    				this.addEdge(currentFunction, currentCallingFunction);
    				this.recursiveRefsFetch(currentCallingFunction);
    			}
    		}
    	}
    	catch (NullPointerException e)
    	{
    		println("Null pointer exception in recursiveRefsFetch from " + currentFunction.getName());
    		throw e;
    	}
    	catch (Exception e)
    	{
    		throw e;
    	}
    }

    private Function askForFunction() throws Exception {
    	try 
    	{
    		throw new Exception();
    	}
    	catch (Exception e)
    	{
    		throw e;
    	}
    }
    
    private void initiateDotFile(String name) throws Exception {
    	// Open file
    	// Write the initial lines:
    	/**
    	 *  digraph code {
			rankdir=LR;
			outputorder=edgesfirst;
			graph [bgcolor=azure fontname="Courier" splines="curved"];
			node [penwidth=4 fillcolor=white style=filled fontname="Courier New Bold" fontsize=14 shape=box];
			edge [arrowhead="normal" style=bold weight=2];
    	 */
    	this.dotLines = new Vector<String>();
    	String[] lines = new String[] {"digraph code {",
    			"rankdir=LR;","outputorder=edgesfirst;",
    			"graph [bgcolor=azure fontname=\"Courier\" splines=\"curved\"];",
    			"node [penwidth=4 fillcolor=white style=filled fontname=\"Courier New Bold\" fontsize=14 shape=box];",
    			"edge [arrowhead=\"normal\" style=bold weight=2];"};
    	for (String line : lines)
    	{
    		this.dotLines.add(line);
    	}
    }

    private void writeToFile() throws Exception {
    	try
    	{
    		this.dotLines.add("}");
		String filename = "deepgraph.txt";
		FileWriter writer = new FileWriter(filename); 
		for(String str: this.dotLines) {
  			writer.write(str + System.lineSeparator());
		}
		writer.close();
		println("Written dot file in " + filename);
    	}
    	catch(Exception e)
    	{
		println("An error occurred when writing to file, printing dot content here:");
    		for (int i = 0; i < this.dotLines.size(); i++)
    		{
    			println(this.dotLines.get(i));
    		}
    	}
    }
    
    private void addNode(Function currentFunction) throws Exception {
    	try
    	{
    		if (!this.nodesList.contains(currentFunction))
    		{
    			this.nodesList.add(currentFunction);
	    		//"0x0041d759" [label="entry0" URL="entry0/0x0041d759"];
    			println("Adding node " + currentFunction.getName());
	    		String lineNode = "\"" + currentFunction.getName() + "\" [label=\"" + currentFunction.getName() + "\"" + " URL=\"" + currentFunction.getName() + "\"];";
	    		this.dotLines.add(lineNode);
    		}
    	}
    	catch(Exception e)
    	{
    		throw e;
    	}
    }
    
    private void addEdge(Function origin, Function destination) throws Exception {
    	try
    	{
    		println("Adding edge " + origin.getName() + " -> " + destination.getName());
    		//"0x0041d759" -> "0x0041d810" [color="#61afef" URL="fcn.0041d810/0x0041d810"];
    		String lineEdge = "\"" + origin.getName() + "\" -> \"" + destination.getName() + "\" [color=\"#61afef\" URL=\"" + origin.getName() + "/" + destination.getName() + "\"];";
    		this.dotLines.add(lineEdge);
    	}
    	catch(Exception e)
    	{
    		throw e;
    	}	
    }
}
