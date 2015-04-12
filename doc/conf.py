# -*- coding: utf-8 -*-

import sys, os, re, subprocess

# -- General configuration -----------------------------------------------------

if os.environ.get('READTHEDOCS', None) == 'True':
  subprocess.call('doxygen')

# Add any Sphinx extension module names here, as strings.
extensions = ['sphinx.ext.todo', 'sphinx.ext.viewcode', 'breathe']

# Breathe configuration
breathe_projects = { "libkresolve": "doxyxml" }
breathe_default_project = "libkresolve"
breathe_domain_by_extension = {"h" : "c"}

# The suffix of source filenames.
source_suffix = '.rst'
master_doc = 'index'

# General information about the project.
project = u'Knot DNS Resolver'
copyright = u'2014-2015 CZ.NIC labs'
version = { k[0][0]: k[0][1] for k in filter(None, [re.findall(r'(MAJOR|MINOR|PATCH) := ([0-9]+)',line) for line in open('../config.mk')])}
version = '%s.%s.%s' % (version['MAJOR'], version['MINOR'], version['PATCH'])
release = version

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ['_build']

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'
highlight_language = 'c'
primary_domain = 'c'

# -- Options for HTML output ---------------------------------------------------

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# If true, SmartyPants will be used to convert quotes and dashes to
# typographically correct entities.
html_use_smartypants = True

# Output file base name for HTML help builder.
htmlhelp_basename = 'apidoc'

# Theme
html_theme = 'sphinx_rtd_theme'

# -- Options for LaTeX output --------------------------------------------------

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title, author, documentclass [howto/manual]).
latex_documents = [
  ('index', 'format.tex', u'Knot DNS Resolver',
   u'CZ.NIC Labs', 'manual'),
]

# -- Options for manual page output --------------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    ('index', 'libkresolve', u'libkresolve documentation',
     [u'CZ.NIC Labs'], 1)
]

