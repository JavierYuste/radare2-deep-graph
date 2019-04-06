import r2pipe
import argparse
from datetime import datetime

parser = argparse.ArgumentParser(description="Obtain a deep callgraph from a given function.")
parser.add_argument("binary", type=str, help="Binary from which the desired callgraph must be obtained")
parser.add_argument("function", type=str, help="Function from where the callgraph must start")
# Make this optional
parser.add_argument("-o", dest='output', type=str, help="Output file to export the graph in dot format")
args = parser.parse_args()
# Necesito una estructura para guardar todas las funciones cuyas llamadas hemos cogido
# Una funcion para coger las llamadas de una call_entry
# Un string .dot al que ir anadiendo nodos y demas

class deep_callgraph():
    def __init__(self, binary, function):
        try:
            r2 = r2pipe.open(binary)
            r2.cmd('aaa')
            self.graph_dot = """digraph code {
            rankdir=LR;
            outputorder=edgesfirst;
            graph [bgcolor=azure fontname="Courier" splines="curved"];
            node [fillcolor=white style=filled fontname="Courier New Bold" fontsize=14 shape=box];
            edge [arrowhead="normal" style=bold weight=2];"""
            self.used_nodes = []
            r2.cmd('s ' + function)
            function_name = r2.cmd('afi.')
            function_name = function_name.replace("\n", "")
            self.functions_list = r2.cmdj('aflmj')
            # Llamada a funcion recursiva con current_function y .dot
            self.get_calls(function_name)
            r2.quit()
            # Print graph_dot
            self.graph_dot += '\n}'
            # Output graph_dot
        except:
            r2.quit()

    def add_node(self, name):
        if name not in self.used_nodes:
            self.used_nodes.append(name)
            self.graph_dot += '\n"' + name + '" [label="' + name + '"];'

    def add_edge(self, name1, name2):
        self.graph_dot += '\n"' + name1 + '" -> "' + name2 + '" [color="#61afef"];'

    def get_calls(self, name):
        self.add_node(name)
        for function in self.functions_list:
            if function['name'] == name:
                for call in function['calls']:
                    self.add_node(call['name'])
                    self.add_edge(name, call['name'])
                    if call['name'][:3] != 'sym':
                        self.get_calls(call['name'])

    def output_callgraph(self, output):
        # When output name is optional, take date as name like deep_callgraph_x.dot
        if args.output == None:
            output = 'callgraph_' + str(datetime.now())
        elif output[-4:] != '.dot':
            output += '.dot'
        file = open(output, "w")
        file.write(self.graph_dot)
        file.close()

if __name__ == '__main__':
    callgraph = deep_callgraph(args.binary, args.function)
    callgraph.output_callgraph(args.output)