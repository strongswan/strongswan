BEGIN   {
        print "<html>\n<body>"
        print "<h2>Permuted Index of HTML headers in FreeS/WAN documents</h2>"
        print "<h3>Jump to a letter</h3>"
        print "<center><big><strong>"
        print "<a href=\"#0\">numeric</a>"
        print "<a href=\"#a\">A</a>"
        print "<a href=\"#b\">B</a>"
        print "<a href=\"#c\">C</a>"
        print "<a href=\"#d\">D</a>"
        print "<a href=\"#e\">E</a>"
        print "<a href=\"#f\">F</a>"
        print "<a href=\"#g\">G</a>"
        print "<a href=\"#h\">H</a>"
        print "<a href=\"#i\">I</a>"
        print "<a href=\"#j\">J</a>"
        print "<a href=\"#k\">K</a>"
        print "<a href=\"#l\">L</a>"
        print "<a href=\"#m\">M</a>"
        print "<a href=\"#n\">N</a>"
        print "<a href=\"#o\">O</a>"
        print "<a href=\"#p\">P</a>"
        print "<a href=\"#q\">Q</a>"
        print "<a href=\"#r\">R</a>"
        print "<a href=\"#s\">S</a>"
        print "<a href=\"#t\">T</a>"
        print "<a href=\"#u\">U</a>"
        print "<a href=\"#v\">V</a>"
        print "<a href=\"#w\">W</a>"
        print "<a href=\"#x\">X</a>"
        print "<a href=\"#y\">Y</a>"
        print "<a href=\"#z\">Z</a>"
        print "</strong></big></center>"
        print "<hr>"
        print "<pre>"
        print "<a name=0>"
        old =""
        }
{       x = tolower(substr($1,1,1))
        if( (x ~ /[a-zA-Z]/) && (x != old) )
                print "<a name=" x ">" $2
        else
                print $2
        old = x
        }
END     { print "</pre>\n</html>" }
