from distutils.core import setup, Extension

ext = Extension('_oxypy', sources=['oxypy.c'])

setup(name='oxypy', version='1.0', description='oxypy', py_modules=['oxypy'], ext_modules=[ext])
