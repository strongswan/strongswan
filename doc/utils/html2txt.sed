# skip over header material
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
# RCSID $Id: html2txt.sed,v 1.1 2004/03/15 20:35:24 as Exp $
/<head>/,/<\/head>/d
/<HEAD>/,/<\/HEAD>/d
/<^body$>/d
s/<body>//
# eliminate possible DOS crud
s/\015//
#get rid of HTML comments
s/<!--.*-->//
/<!--/,/-->/d
# citations & emphasis -> visible
s/<cite>/"/g
s/<\/cite>/"/g
s/<em>/*/g
s/<\/em>/*/g
s/<strong>/!->/g
s/<\/strong>/<-!/g
s/<b>//g
s/<\/b>//g
s/<blockquote>/Quote -->/
s/<\/blockquote>/<-- End Quote/
# mark headers
s/<h1>/Header 1:  /
s/<h2>/Header 2:  /
s/<h3>/Header 3:  /
s/<h4>/Header 4:  /
s/<h5>/Header 5:  /
s/<h6>/Header 6:  /
# remove some cruft
s/<\/h[1-6]>//
/^<a name=[a-zA-Z0-9\.]*>$/d
s/<a name=[a-zA-Z0-9\.]*>//
# definition lists
s/<dl>//
s/<\/dl>//
s/^<dt>$/-----------------------------------------/
s/^<dt>/-----------------------------------------\
/
s/<dd>/\
/
# other types of lists
s/<li>//
s/<ol>//
s/<ul>//
s/<\/ol>//
s/<\/ul>//
# tables
s/<table>//
s/<\/table>//
s/<tr>//
s/<td>/	/g
# line break and paragraph markers
# different subst depending where they are in line
s/^<br>//
s/<br>$//
s/<br>/\
/
s/^<p>$//
s/<p>$/\
/
s/^<p>/\
/
s/<p>/\
\
/
s/<\/p>//
# remove more cruft
s/<pre>//
s/<\/pre>//
s/<\/body>//
s/<\/html//
s/<\/BODY>//
s/<\/HTML>//
