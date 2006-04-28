# turn end-of xref tags into <*>
# Copyright (C) 1999  Sandy Harris.
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# RCSID $Id: xref.sed,v 1.1 2004/03/15 20:35:24 as Exp $
s/<\/a>/<*>/g
# delete all xrefs that point
# within our document set
s/<a href="..\/Internet-docs\/rfc....\.txt">//
# in same doc
s/<a href="#[a-zA-Z0-9\.]*">//
# pointer into another doc
s/<a href="DES.html#[a-zA-Z0-9\.]*">//
s/<a href="RFCs.html#[a-zA-Z0-9\.]*">//
s/<a href="WWWref.html#[a-zA-Z0-9\.]*">//
s/<a href="bibliography.html#[a-zA-Z0-9\.]*">//
s/<a href="compatibility.html#[a-zA-Z0-9\.]*">//
s/<a href="configuration.html#[a-zA-Z0-9\.]*">//
s/<a href="contents.html#[a-zA-Z0-9\.]*">//
s/<a href="debugging.html#[a-zA-Z0-9\.]*">//
s/<a href="exportlaws.html#[a-zA-Z0-9\.]*">//
s/<a href="glossary.html#[a-zA-Z0-9\.]*">//
s/<a href="index.html#[a-zA-Z0-9\.]*">//
s/<a href="overview.html#[a-zA-Z0-9\.]*">//
s/<a href="roadmap.html#[a-zA-Z0-9\.]*">//
s/<a href="testbed.html#[a-zA-Z0-9\.]*">//
s/<a href="setup.html#[a-zA-Z0-9\.]*">//
# pointer to head of doc
s/<a href="DES.html">//
s/<a href="RFCs.html">//
s/<a href="WWWref.html">//
s/<a href="bibliography.html">//
s/<a href="compatibility.html">//
s/<a href="configuration.html">//
s/<a href="contents.html">//
s/<a href="debugging.html">//
s/<a href="exportlaws.html">//
s/<a href="glossary.html">//
s/<a href="index.html">//
s/<a href="overview.html">//
s/<a href="roadmap.html">//
s/<a href="testbed.html">//
s/<a href="setup.html">//
# xref to non-HTML files
s/<a href="standards">//
s/<a href="impl.notes">//
s/<a href="prob.report">//
