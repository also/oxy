from distutils.core import setup, Extension

ext = Extension('oxypy', sources=['oxypy.c'])

setup(name='oxypy', version='1.0', description='oxypy', ext_modules=[ext])
