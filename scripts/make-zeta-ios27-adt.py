#!/usr/bin/env python3
"""UniXNU payload entry point for the experimental iPhone Duo/V68 persona.

The payload builder invokes this tool using its existing ADT argument contract;
no upstream CLI changes are needed. All hardware nodes remain zeta's.
"""
import runpy
from pathlib import Path


if __name__ == '__main__':
    generator = runpy.run_path(str(Path(__file__).with_name('make-zeta-adt.py')))
    generator['main'](default_identity='iPhone19,4')
