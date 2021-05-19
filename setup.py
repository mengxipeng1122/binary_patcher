#!/usr/bin/env python

from setuptools import find_packages, setup, Command

REQUIRES_PYTHON = '>=3.6.0'
setup(
        name='BinaryPatcher',
        version='0.0.1',
        scripts=['scripts/binaryPatcher.py', 'scripts/encryptELF.py'],
        description='a static binary patching framework',
        author='Meng Xipeng',
        author_email='mengxipeng@gmail.com',
        packages=find_packages(),
        python_requires=REQUIRES_PYTHON,
        zip_safe=False,
   )
