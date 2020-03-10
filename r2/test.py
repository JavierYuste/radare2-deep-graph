import r2pipe
r2 = r2pipe.open()
name = r2.cmd("afi")
print(name)
