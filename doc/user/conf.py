# SPDX-License-Identifier: GPL-3.0-or-later

import os
import re

import sphinx_rtd_theme

# -- General configuration -----------------------------------------------------

# General information about the project.
project = u'Knot Resolver'
copyright = u'CZ.NIC labs'
with open('../../meson.build') as f:
    for line in f:
        match = re.match(r"\s*version\s*:\s*'([^']+)'.*", line)
        if match is not None:
            version = match.groups()[0]
release = version

# Add any Sphinx extension module names here, as strings.
extensions = [
    'sphinx.ext.todo',
    'sphinx.ext.viewcode',
    'sphinx_tabs.tabs',
]

theme_major = sphinx_rtd_theme.__version__.partition('.')[0]
if theme_major >= '2':
    extensions.append('sphinxcontrib.jquery')

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ['_build']

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'friendly'

# -- Options for HTML output ---------------------------------------------------

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['../_static']

# Theme
html_theme = 'sphinx_rtd_theme'

html_theme_options = {
    'logo_only': True,  # if we have a html_logo below, this shows only the logo with no title text
    # ToC options
    'collapse_navigation': False,
    'sticky_navigation': True,
}
html_logo = '../_static/logo-negativ.svg'
html_css_files = [
    'css/custom.css',
    'css/user.css',
]

# reStructuredText that will be included at the beginning of every source file that is read.
# This is a possible place to add substitutions that should be available in every file.
rst_prolog = """
.. |yaml| replace:: YAML
.. |lua| replace:: Lua
"""
