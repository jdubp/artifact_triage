#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import glob

# Get all plugins to initiate access for globals() function in main script
plugins = []
for plugin in glob.glob(os.getcwd() + '//**/*' + 'plugin_*.py'):
    plugins.append(os.path.basename(plugin).split('.')[0])

__all__ = plugins