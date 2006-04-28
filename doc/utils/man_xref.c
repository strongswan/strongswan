#include <stdio.h>
#include <ctype.h>
#include <assert.h>

/*
	look through HTMLized man pages
	convert references like man(1) into HTML links

	somewhat quick & dirty code
	various dubious assumptions made:

	[a-zA-Z0-9\-_\.]* defines legal characters in name
	pagename(x) corresponds to pagename.x.html
	(Fine *if* it's been converted by my scripts)
	x in the above must be a single digit
	(or we ignore it, which does no damage)
	Lazy parsing: malloc() enough RAM to read in whole file
	Limited syntax: exactly one input file, results to stdout 

	Sandy Harris
*/

int do_file( char *, char *) ;

main(int argc, char **argv)
{
	FILE *in ;
	char *progname;
	long lsize ;
	size_t size, nread;
	char *buffer, *bufend ; 
	progname = *argv ;
	if( argc != 2 )	{
		fprintf(stderr,"usage: %s input-file\n", progname);
		exit(1) ;
	}
	if( (in = fopen(argv[1],"r")) == NULL )	{
		fprintf(stderr,"%s Can't open input file\n", progname);
		exit(2) ;
	}
	if( (lsize = fseek(in, 0L, SEEK_END)) < 0L )	{
		fprintf(stderr,"%s fseek() fails\n", progname);
		exit(3) ;
	}
	lsize = ftell(in) ;
	rewind(in) ;
	size = (size_t) lsize ;
	if( lsize != (long) size )	{
		fprintf(stderr,"%s file too large\n", progname);
		exit(4) ;
	}
	if( (buffer = (char *) malloc(size)) == NULL)	{
		fprintf(stderr,"%s malloc() failed\n", progname);
		exit(5) ;
	}
	bufend = buffer + size ;
	if( (nread = fread(buffer, size, 1, in)) != 1) { 
		fprintf(stderr,"%s fread() failed\n", progname);
		exit(6) ;
	}
	do_file(buffer,bufend);
}

do_file(char *start, char *end)
{
	/* p is where to start parsing, one past last output	*/
	/* q is how far we've parsed				*/
	char *p, *q ;
	int value ;
	for( p = q = start ; p < end ; q = (q<end) ? (q+1) : q  )	{
		/* if p is beyond q, catch up	*/
		if( q < p )
			continue ;
		/* move q ahead until we know if we've got manpage name */
		if( isalnum(*q) )
			continue ;
		switch(*q)	{
			/* can appear in manpage name	*/
			case '.':
			case '_':
			case '-':
			case '(':
				continue ;
				break ;
			/* whatever's between p and q
			   is not a manpage name
			   so output it
			*/
			default:
				/* leave p one past output	*/
				for( ; p <= q ; p++ )
					putchar(*p);
				break ;
			/* we may have a manpage name	*/
			case ')':
				value = do_name(p,q);
				if(value)	{
					p = q ;
					p++ ;
				}
				/* unreached with current do_name() */
				else
					for( ; p <= q ; p++ )
						putchar(*p);
				break ;
}	}	}

do_name(char *p, char *q)
{
	*q = '\0' ;
	/* if end of string matches RE ([0-9])
	   with at least one legal character before it
	   add HTML xref stuff
	*/
	if( (q-p > 3) && isdigit(q[-1]) && (q[-2]=='('))	{
		q[-2] = '\0' ;
		q-- ;  
		printf("<a href=\"%s.%s.html\">", p, q);
		printf("%s(%s)", p, q);
		printf("</a>");
	}
	// otherwise just print string
	else	printf("%s)", p);
	return 1 ;
}
