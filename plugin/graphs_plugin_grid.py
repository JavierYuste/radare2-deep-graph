import cutter

from PySide2.QtCore import QObject, SIGNAL, Qt
from PySide2.QtWidgets import QAction, QVBoxLayout, QLabel, QWidget, QSizePolicy, QPushButton, QComboBox, QLineEdit, QGroupBox, QGridLayout


class DeepGraphs(cutter.CutterDockWidget):
    def __init__(self, parent, action):
        super(DeepGraphs, self).__init__(parent, action)
        self.setObjectName("DeepGraphs")
        self.setWindowTitle("Deep graphs")

        content = QWidget()
        self.setWidget(content)

        # Create layout
        self.horizontalGroupBox = QGroupBox("Grid")

        layout = QGridLayout()
        layout.setColumnStretch(1, 4)
        layout.setColumnStretch(2, 4)
        layout.setColumnStretch(3, 4)
        layout.setColumnStretch(4, 4)
        layout.setColumnStretch(5, 4)
        layout.setColumnStretch(6, 4)

        self.output_path = QLineEdit(content)
        self.output_path.setText("PATH")
        layout.addWidget(self.output_path, 0, 3)
        layout.setAlignment(self.output_path, Qt.AlignHCenter)

        self.combo = QComboBox(content)
        self.combo.addItem("Graphviz dot")
        self.combo.addItem("Graph Modelling Language (gml)")
        self.combo.addItem("Json")
        layout.addWidget(self.combo, 0, 4)
        layout.setAlignment(self.combo, Qt.AlignHCenter)

        # TODO: This graph is not available due to an issue on radare2 (see closed issue #13590). It will be available as soon as Cutter updates its radare2 version.
        deep_button = QPushButton(content)
        deep_button.setText("Deep callgraph")
        deep_button.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        deep_button.setMaximumHeight(50)
        deep_button.setMaximumWidth(200)
        layout.addWidget(deep_button, 2, 2)
        layout.setAlignment(deep_button, Qt.AlignHCenter)

        global_button = QPushButton(content)
        global_button.setText("Global callgraph")
        global_button.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        global_button.setMaximumHeight(50)
        global_button.setMaximumWidth(200)
        layout.addWidget(global_button, 3, 3)
        layout.setAlignment(global_button, Qt.AlignHCenter)

        function_button = QPushButton(content)
        function_button.setText("Function callgraph")
        function_button.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        function_button.setMaximumHeight(50)
        function_button.setMaximumWidth(200)
        layout.addWidget(function_button, 2, 3)
        layout.setAlignment(function_button, Qt.AlignHCenter)

        global_data_x_button = QPushButton(content)
        global_data_x_button.setText("Global data references")
        global_data_x_button.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        global_data_x_button.setMaximumHeight(50)
        global_data_x_button.setMaximumWidth(200)
        layout.addWidget(global_data_x_button, 3, 4)
        layout.setAlignment(global_data_x_button, Qt.AlignHCenter)

        function_data_x_button = QPushButton(content)
        function_data_x_button.setText("Function data references")
        function_data_x_button.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        function_data_x_button.setMaximumHeight(50)
        function_data_x_button.setMaximumWidth(200)
        layout.addWidget(function_data_x_button, 2, 4)
        layout.setAlignment(function_data_x_button, Qt.AlignHCenter)

        global_refs_button = QPushButton(content)
        global_refs_button.setText("Global references")
        global_refs_button.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        global_refs_button.setMaximumHeight(50)
        global_refs_button.setMaximumWidth(200)
        layout.addWidget(global_refs_button, 3, 5)
        layout.setAlignment(global_refs_button, Qt.AlignHCenter)

        xrefs_button = QPushButton(content)
        xrefs_button.setText("Function xrefs")
        xrefs_button.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        xrefs_button.setMaximumHeight(50)
        xrefs_button.setMaximumWidth(200)
        layout.addWidget(xrefs_button, 2, 5)
        layout.setAlignment(xrefs_button, Qt.AlignHCenter)

        imports_button = QPushButton(content)
        imports_button.setText("Imports refs")
        imports_button.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        imports_button.setMaximumHeight(50)
        imports_button.setMaximumWidth(200)
        layout.addWidget(imports_button, 3, 2)
        layout.setAlignment(imports_button, Qt.AlignHCenter)

        self.horizontalGroupBox.setLayout(layout)

        layout = QVBoxLayout(content)
        layout.addWidget(self.horizontalGroupBox)
        content.setLayout(layout)

        QObject.connect(deep_button, SIGNAL("clicked()"), self.generate_callgraph)
        QObject.connect(global_button, SIGNAL("clicked()"), self.generate_global_callgraph)
        QObject.connect(function_button, SIGNAL("clicked()"), self.generate_local_callgraph)
        QObject.connect(global_data_x_button, SIGNAL("clicked()"), self.generate_global_data_references)
        QObject.connect(function_data_x_button, SIGNAL("clicked()"), self.generate_local_data_references)
        QObject.connect(global_refs_button, SIGNAL("clicked()"), self.generate_global_refs)
        QObject.connect(xrefs_button, SIGNAL("clicked()"), self.generate_xrefs)
        QObject.connect(imports_button, SIGNAL("clicked()"), self.generate_imports_graph)

        self.show()


    def generate_callgraph(self):
        # TODO: get user settings for the .dot graph instead of using this hardcoded settings
        self.graph_dot = """digraph code {
        rankdir=LR;
        outputorder=edgesfirst;
        graph [bgcolor=azure fontname="Courier" splines="curved"];
        node [fillcolor=white style=filled fontname="Courier New Bold" fontsize=14 shape=box];
        edge [arrowhead="normal" style=bold weight=2];"""
        self.used_nodes = []
        function_name = cutter.cmd('afi.')
        function_name = function_name.replace("\n", "")
        self.functions_list = cutter.cmdj('aflmj')
        self.get_calls(function_name)
        self.graph_dot += '\n}'

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

    def output_callgraph(self):
        output = 'deep_callgraph_' + cutter.cmd('afi.') + self.get_output_format_extension(self.combo.currentIndex())
        file = open(output, "w")
        file.write(self.graph_dot)
        file.close()

    def generate_global_callgraph(self):
        # agC
        name = self.get_output_name("global_callgraph")
        command = "agC" + self.get_output_format_cmd(self.combo.currentIndex())
        cutter.cmd(command + " > " + name)

    def generate_local_callgraph(self):
        # agc
        function_name = self.get_output_name("callgraph", function=True)
        command = "agc" + self.get_output_format_cmd(self.combo.currentIndex())
        command += " > "
        command += function_name
        cutter.cmd(command)

    def generate_global_data_references(self):
        # agA
        name = self.get_output_name("global_data_references")
        command = "agA" + self.get_output_format_cmd(self.combo.currentIndex())
        cutter.cmd(command + " > " + name)

    def generate_local_data_references(self):
        # aga
        function_name = self.get_output_name("data_references", function=True)
        command = "aga" + self.get_output_format_cmd(self.combo.currentIndex())
        command += " > "
        command += function_name
        cutter.cmd(command)

    def generate_global_refs(self):
        # agR
        name = self.get_output_name("global_references")
        command = "agR" + self.get_output_format_cmd(self.combo.currentIndex())
        cutter.cmd(command + " > " + name)

    def generate_xrefs(self):
        # agx
        function_name = self.get_output_name("xrefs", function=True)
        command = "agx" + self.get_output_format_cmd(self.combo.currentIndex())
        command += " > "
        command += function_name
        cutter.cmd(command)

    def generate_imports_graph(self):
        # agi
        name = self.get_output_name("imports_refs")
        command = "agi" + self.get_output_format_cmd(self.combo.currentIndex())
        cutter.cmd(command + " > " + name)

    def get_output_name(self, graph_name, function=False):
        if not function:
            name = graph_name + "." + self.get_output_format_extension(self.combo.currentIndex())
            return self.append_to_path(name)
        else:
            function_name = cutter.cmd('afi.')
            function_name = function_name.replace("\n", "")
            function_name += "_"
            function_name += graph_name
            function_name += "."
            function_name += self.get_output_format_extension(self.combo.currentIndex())
            return self.append_to_path(function_name)

    def append_to_path(self, name):
        path = self.output_path.text()
        if path != "PATH":
            if path[-1:] != '/':
                path += '/'
            name = str(path) + name
        return name

    def get_output_format_extension(self, index):
        if index == 0:
            return "dot"
        elif index == 1:
            return "gml"
        elif index == 2:
            return "json"
        else:
            return "none"

    def get_output_format_cmd(self, index):
        if index == 0:
            return "d"
        elif index == 1:
            return "g"
        elif index == 2:
            return "j"
        else:
            return ""


class DeepGraphsPlugin(cutter.CutterPlugin):
    name = "DeepGraphs"
    description = "Graphs builder plugin"
    version = "0.2"
    author = "Javier Yuste"

    def __init__(self):
        super(DeepGraphsPlugin, self).__init__()

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        action = QAction("DeepGraphs", main)
        action.setCheckable(True)
        widget = DeepGraphs(main, action)
        main.addPluginDockWidget(widget, action)

    def terminate(self): # optional
        print("DeepGraphs plugin shutting down")


# This function will be called by Cutter and should return an instance of the plugin.
def create_cutter_plugin():
    return DeepGraphsPlugin()