# radare2-deep-graphs
A Cutter plugin to generate radare2 graphs. It also provides a new graph called _Deep callgraph_, which builds an in-depth callgraph from the current function, adding recursively its callees' callings.

## Use
By default, on Linux, Cutter loads python plugins from $HOME/.local/share/RadareOrg/Cutter/plugins/python. You just need to copy one of the files under the [plugins folder](https://github.com/JavierYuste/radare2-deep-graphs/tree/master/plugin) on that path.

Output format and output path can be specified on the plugin's window. By default, graphs are saved as dot files on the current directory, from where Cutter was launched.

![alt text](https://github.com/JavierYuste/radare2-deep-graphs/blob/master/images/GridLayout.png "GridLayout")


## Command line use
The _Deep callgraph_ graph can also be generated from the command line, see the script on the [script directory](https://github.com/JavierYuste/radare2-deep-graphs/tree/master/script).

![alt text](https://github.com/JavierYuste/radare2-deep-graphs/blob/master/images/CommandLineUse.png "Command line script")

## TODO
- _Deep callgraph_ graphs are broken due to a now solved issue, see [closed issue #13590](https://github.com/radare/radare2/issues/13590). These graphs will be available on the Cutter plugin as soon as they update their radare2 version.
- Take _Deep callgraph_ settings from the user settings.
