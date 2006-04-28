/*
	extract headers from HTML files
	in format suitable for turning into permuted index
*/

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
	maximum sizes for input line and for name in <a> tag
*/
#define MAX_LINE  512
#define MAX_NAME   64

/*
	functions
	all return 0 for OK, 1 for errors
*/
int do_file( char *, FILE * ) ;
int parse_line( char * ) ;
int print_line( char *, char *) ;
int print_header_problem( char * ) ;
int sanity() ;

void die( char * ) ;

char	*prog_name ;
int	max_level ;
char	*current_file ;

int main(int argc, char* argv[])
{
	char *p ;
	int temp, done, status ;
	FILE *fp ;

	prog_name = *argv ;
	argc--,argv++ ;

	max_level = 9 ;	
	if(argc && *argv )	{
		p = *argv ;
		if( p[0] == '-' )	{
			if( isdigit(p[1]) && p[2] == '\0' )	{
				max_level = p[1] - 0 ;
				argc-- ;
				argv++ ;
			}
			else die("unknown option") ;
	}	}

	status = done = 0 ;
	if( argc == 0)	{
		if( (status = do_file("STDIN", stdin)) == 0 )
			done++ ;
	}
	else	{
/*
		printf("ARGC = %d\n", argc ) ;
*/
		while( argc-- )	{
			p = *argv++ ;
/*
			printf("ARGV P %s %s\n", *argv, p) ;
*/
			if( p == NULL )	{
				fprintf(stderr, "%s: null filename pointer\n", prog_name) ;
				status++ ;
			} 
			else if( (fp = fopen(p,"r")) == NULL )	{
				fprintf(stderr, "%s: cannot open file %s\n", prog_name, p) ;
				status++ ;
			}
			else	{
				if( (temp = do_file(p, fp)) != 0 )
					status++ ;
				done++ ;
				fclose(fp) ;
			}
			fflush(stderr) ;
			fflush(stdout) ;
		}
	}
/*
	printf("%s: %d files processed, %d with errors\n", prog_name, done, status) ;
*/
	return( status ? 1 : 0 ) ;
}

void die( char *message )
{
	fflush(stdout) ;
	fprintf(stderr, "%s: %s\n", prog_name, message) ;
	exit(1) ;
}

int header_flags[10] ;
int in_header ;

char buffer[MAX_LINE+1] ;
char label[MAX_NAME+1] ;

int do_file( char *file, FILE *fp )
{
	int i, status, x, y ;
	char *base, *p ;

	status = 0 ;
	in_header = 0 ;
	label[0] = '\0' ;
	for( i = 0 ; i < 10 ; i++ )
		header_flags[i] = 0 ;
	current_file = file ;

	while( base = fgets(buffer, MAX_LINE, fp) )	{
		// count < and > characters in line
		for( x = y = 0, p = base ; *p ; p++ )
			switch( *p )	{
				case '<':
					x++ ;
					break ;
				case '>':
					y++ ;
					break ;
				default:
					break ;
			}
		// skip line if no < or >
		if( x == 0 && y == 0 )
			continue ;
		// report error for unequal count
		else if( x != y )	{
			if( strncmp( base, "<!--", 4) && strncmp(base, "-->", 3) )	{
				fflush(stdout) ;
				fprintf(stderr, "%s in file %s: unequal < > counts %d %d\n",
					prog_name, file, x, y ) ;
				fprintf(stderr, "%s: %s\n", prog_name, base) ;
				fflush(stderr) ;
				status = 1 ;
			}
			continue ;
		}
		// parse lines containing tags
		else
			if( parse_line(base) )
				status = 1 ;
		// check that header labelling is sane
		for( i = x = y = 0 ; i < 10 ; i++ )	{
			// count non-zero entries
			if( x = header_flags[i] )
				y++ ;
			// should be in 0 or 1 headers at a time
			if( x > 1 || x < 0 )
				status = 1 ;
		}
		if( y > 1 )
			status = 1 ;
	}
	return status ;
}

int parse_line( char *data )
{
	char *p, *q, *end ;
	int x ;

	// set end pointer
	for( end = data ; *end ; end++ )
		;
	// trim off trailing returns or newlines
	for( p = end - 1, q = end ; q > data ; p--,q-- )	{
		switch( *p )	{
			case '\012':
			case '\015':
				*p = '\0' ;
				continue ;
			default:
				break ; // out of switch()
		}
		break ; // out of for()
	}
	end = q ;
	p = data ;
	while( p < end )	{
		// find tag delimiters
		if( *p == '<')	{
			for( q = p + 1 ; *q ; q++ )
				if( *q == '<' || *q == '>' )
					break ;
			// if we find another '<'
			// restart tag search from it
			if( *q == '<' )	{
				p = q ;
				continue ;
			}
			// "<>" is not interesting
			if( q == p + 1 )	{
				fflush(stdout) ;
				fprintf(stderr, "%s: null tag\n", prog_name) ;
				fprintf(stderr, "%s: line\n", prog_name, data) ;
				fflush(stderr) ;
				p = q + 1 ;
				continue ;
			}
			// ignore delimiters once found
			*q = '\0' ;
			p++ ;
			// p points to tag contents, null terminated
			switch( *p )	{
			// save contents of <a name= > tags
			case 'a' :
			case 'A' :
				if(	 p[1] == ' ' &&
					(p[2] == 'n' || p[2] == 'N') &&
					(p[3] == 'a' || p[3] == 'A') &&
					(p[4] == 'm' || p[4] == 'M') &&
					(p[5] == 'e' || p[5] == 'E') &&
					 p[6] == '=' )
				strncpy(label, p + 7, MAX_NAME) ;
				break ;
			case 'b' :
			case 'B' :
				if(	in_header && strlen(p) == 2 &&
					(p[1] == 'r' || p[1] == 'R') )
					putchar(' ') ;
				break ;
			// header tags
			case 'h' :
			case 'H' :
				if( strlen(p) == 2 && isdigit(p[1]) )	{
					if( in_header )
						fprintf(stderr, "%s: bad header nesting in %s\n",
							prog_name, current_file) ; 
					x = p[1] - '0' ;
					in_header = 1 ;
					header_flags[x]++ ;
					printf("%s\t%s\tH%d\t", current_file, label, x) ;
				}
				break ;
			// only care about end-of-header
			case '/':
				p++ ;
				switch( *p )	{
				case 'h' :
				case 'H' :
					if( strlen(p) == 2 && isdigit(p[1]) )	{
						if( ! in_header )
							fprintf(stderr, "%s: bad header nesting in %s\n",
								prog_name, current_file) ; 
						x = p[1] - '0' ;
						in_header = 0 ;
						header_flags[x]-- ;
						printf("\n") ;
					}
					break ;
				}
				break ;
			// uninteresting tag, look for next
			default :
				break ;
			}
		// tag done, point p beyond it
		p = q + 1 ;
		}
		else if( in_header )	{
			if( isprint(*p) && *p != '\n' )
				putchar(*p) ;
			else
				putchar(' ');
			p++ ;
		}
		else
			p++ ;
	}
	return(0) ;
}

int print_line( char *tag, char *text)
{
	printf("%%s\ts\t%s\t%s\t\n", current_file, label, tag, text) ;
	return 0 ;
}

int print_header_problem( char *file )
{
	int i ;
	fflush(stdout) ;
	fprintf(stderr, "%s: HEADER TAG PROBLEM in file %s\n", prog_name, file) ;
	fprintf(stderr, "%s: counts", prog_name) ;
	for ( i = 0 ; i < 10 ; i++ )
		fprintf(stderr, "\t%d", i) ;
	fprintf(stderr,"\n") ;
	fflush(stderr) ;
	return(0) ;
}

