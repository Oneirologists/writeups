import pickle, sys, py_compile

pyc = py_compile.compile(sys.argv[1])
a = open(pyc, 'rb').read()

with open('test.pyc', 'wb') as out:
    out.write(b'!' + pickle.dumps(a))
