#!/usr/bin/python3
import r2pipe

class deep_callgraph():
    def __init__(self):
        try:
            r2 = r2pipe.open()
            self.graph_dot = """digraph code {
            rankdir=LR;
            outputorder=edgesfirst;
            graph [bgcolor=azure fontname="Courier" splines="curved"];
            node [fillcolor=white style=filled fontname="Courier New Bold" fontsize=14 shape=box];
            edge [arrowhead="normal" style=bold weight=2];"""
            self.used_nodes = []
            print("NAme")
            function_name = r2.cmdj('afij')
            function_name = function_name['name']
            function_name = function_name.replace("\n", "")
            print("list")
            self.functions_list = r2.cmdj('aflmj')
            self.get_calls(function_name)
            self.graph_dot += '\n}'
            print("output")
            self.output_callgraph(function_name)
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
        try:
            function_name = output
            function_name += "_deep_callgraph.dot"
            file = open(output, "w")
            file.write(self.graph_dot)
            file.close()
        except Exception as e:
            print(e)

if __name__ == '__main__':
    callgraph = deep_callgraph()
