# table-of-contents extractor
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
# RCSID $Id: contents.awk,v 1.1 2004/03/15 20:35:24 as Exp $
BEGIN	{
	# initialise indent counter
	indent = 0
	# define variables for section breaks
	b0 = "==================================================="
	b1 = "---------------------------------------------------"
	b2 = "\t------------------------------------------"
	# TURN OFF HTML formatting
	print "<html>"
	print "<body>"
	print "<pre>"
	# print a header
	blurb() 
	print "Section headings printed, indentation shows structure"
}
# start of new file
FNR == 1 {
	print b0
	print "HTML file: " "<a href=\"" FILENAME "\">" FILENAME "</a>"
	print b1
}
# print header lines
# actual printing is done by tagged() function
# which adds tag if last line was <a name=...>
$0 ~/<h1>/	{
	text = $0
	tabs = ""
	gsub(/.*<h1>/, "", text)
	gsub(/<\/h1>/, "", text)
	tagged( text )
}
$0 ~/<h2>/	{
	text = $0
	tabs = "\t"
	gsub(/.*<h2>/, "", text)
	gsub(/<\/h2>/, "", text)
	tagged(text)
}
$0 ~/<h3>/	{
	text = $0
	tabs = "\t\t"
	gsub(/.*<h3>/, "", text)
	gsub(/<\/h3>/, "", text)
	tagged(text)
}
$0 ~/<h4>/	{
	text = $0
	tabs = "\t\t\t"
	gsub(/.*<h4>/, "", text)
	gsub(/<\/h4>/, "", text)
	tagged( text )
}
# if current line is not header
# and we have stored tag from <a name=..> line
# make link to that tag
$0 !~ /<h[1-4]/ 	{
	if( length(name) )
		print "[ <a href=\"" FILENAME "#" name "\">" name "</a>" " ]"
	name = ""
}
# for <a name=whatever> lines
# save name in a variable
# not printed until we see next line
$0 ~ /<a name=.*>/	{
	name = $0
	# strip anything before or after name tag
	gsub(/.*<a name=/, "", name)
	gsub(/>.*/, "", name)
	# strip quotes off name
	gsub(/^"/, "", name)
	gsub(/"$/, "", name)
}
END	{
	print b0
	blurb()
	print "Docs & script by Sandy Harris"
	print "</pre>"
	print "</body>"
	print "</html>"
}

function tagged(text)	{	# print header with tag if available
	if( length(name) )	# > 0 if previous line was a name
		print tabs "<a href=\"" FILENAME "#" name "\">" text "</a>"
	else
		print tabs text
	name = ""
}

function blurb()	{
	print "Linux FreeSWAN HTML documents"
	print "Automatically generated Table of Contents"
	print "Bug reports to the mailing list: linux-ipsec@clinet.fi"
	print "<p>"
}
