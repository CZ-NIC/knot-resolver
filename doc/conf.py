# SPDX-License-Identifier: GPL-3.0-or-later
# -*- coding: utf-8 -*-

import os
import re
import subprocess

import sphinx_rtd_theme

# -- General configuration -----------------------------------------------------

if os.environ.get('READTHEDOCS', None) == 'True':
    subprocess.call('doxygen')

# Add any Sphinx extension module names here, as strings.
extensions = ['sphinx.ext.todo', 'sphinx.ext.viewcode', 'breathe']

# Breathe configuration
breathe_projects = {"libkres": "doxyxml"}
breathe_default_project = "libkres"
breathe_domain_by_extension = {"h": "c"}

# The suffix of source filenames.
source_suffix = '.rst'
master_doc = 'index'

# General information about the project.
project = u'Knot Resolver'
copyright = u'2014-2020 CZ.NIC labs'
with open('../meson.build') as f:
    for line in f:
        match = re.match(r"\s*version\s*:\s*'([^']+)'.*", line)
        if match is not None:
            version = match.groups()[0]
release = version

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ['_build']

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'
highlight_language = 'c'
primary_domain = 'py'

# -- Options for HTML output ---------------------------------------------------

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# Output file base name for HTML help builder.
htmlhelp_basename = 'apidoc'

# Theme
html_theme = 'sphinx_rtd_theme'
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]

html_theme_options = {
    'logo_only': True,  # if we have a html_logo below, this shows only the logo with no title text
    # Toc options
    'collapse_navigation': False,
    'sticky_navigation': True,
}
html_logo = '_static/logo-negativ.svg'
html_style = 'css/custom.css'

# -- Options for LaTeX output --------------------------------------------------

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title, author, documentclass [howto/manual]).
latex_documents = [
  ('index', 'format.tex', u'Knot Resolver',
   u'CZ.NIC Labs', 'manual'),
]

# -- Options for manual page output --------------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    ('index', 'libkres', u'libkres documentation',
     [u'CZ.NIC Labs'], 1)
]
