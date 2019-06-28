import r2pipe
import argparse
from datetime import datetime

parser = argparse.ArgumentParser(description="Obtain a deep callgraph from a given function.")
# Make this optional
parser.add_argument("-o", dest='output', type=str, help="Output file to export the graph in dot format")
parser.add_argument("-f", dest='function', type=str, help="Function address")
args = parser.parse_args()
# Necesito una estructura para guardar todas las funciones cuyas llamadas hemos cogido
# Una funcion para coger las llamadas de una call_entry
# Un string .dot al que ir anadiendo nodos y demas

class deep_callgraph():
    def __init__(self):
        try:
            print("Starting")
            r2 = r2pipe.open()
            print("Opened pipe")
            self.graph_dot = """digraph code {
            rankdir=LR;
            outputorder=edgesfirst;
            graph [bgcolor=azure fontname="Courier" splines="curved"];
            node [fillcolor=white style=filled fontname="Courier New Bold" fontsize=14 shape=box];
            edge [arrowhead="normal" style=bold weight=2];"""
            self.used_nodes = []
            r2.cmd('s')
            print('wtf')
            r2.cmd('s ' + str(args.function))
            print("Here?")
            print(r2.cmd('s'))
            function_name = r2.cmdj('afij')
            function_name = function_name['name']
            print("Before")
            function_name = function_name.replace("\n", "")
            print("Function name: " + function_name)
            self.functions_list = r2.cmdj('aflmj')
            print("Obtained functions list")
            # Llamada a funcion recursiva con current_function y .dot
            self.get_calls(function_name)
            # Print graph_dot
            self.graph_dot += '\n}'
            # Output graph_dot
            self.output_callgraph("deep.dot")
        except:
            pass

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
                    print(call['name'])
                    self.add_node(call['name'])
                    self.add_edge(name, call['name'])
                    #if call['name'][:3] != 'sym':
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
    callgraph = deep_callgraph()
