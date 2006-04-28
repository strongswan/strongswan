#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define MAX_LINE  512

void die( char * ) ;

char buffer[MAX_LINE+1] ;
char *prog_name ;

void die( char *message )
{
	fflush(stdout) ;
	fprintf(stderr, "%s: %s\n", prog_name, message) ;
	exit(1) ;
}

int main(int argc, char* argv[])
{
	int errors ;
	prog_name = *argv ;
	if( argc != 1 )
		die("pure filter, takes no arguments") ;
	errors = 0 ;
	while( fgets(buffer, MAX_LINE, stdin))
		errors += do_line(buffer) ;
	exit(errors ? 1 : 0 ) ;
}

int do_line(char *data)
{
	char *p, *q, *r, *end, *before, *after ;
	// expecting two tab-separated fields
	// point r to 2nd, null terminate 1st
	for( r = data ; *r && *r != '\t' ; r++ )
		;
	if( *r != '\t' )
		return(1) ;
	end = r++ ;
	*end = '\0' ;
	for( q = r ; *q ; q++ )
		if( *q == '\n' )
			*q = '\0' ;
	if( !strlen(r) )
		return(1) ;
	// within 1st, parse as space-separated
	// p will point to current word, q past its end
	// before & after point to rest of text
	// spaces converted to nulls & back as req'd
	before = "" ;
	for( p = data ; p < end ; p = q + 1 )	{
		if( p > data )	{
			before = data ;
			p[-1] = '\0' ;
		}
		// find end of word
		for( q = p ; *q && *q != ' ' ; q++ )
			;
		if( q == end )
			after = "" ;
		else if( q < end )	{
			after = q + 1 ;
			*q = '\0' ;
		}
		else	assert(0) ;
		print_line(before, p, after, r) ;
		if( q < end )
			*q = ' ' ;
		if( p > data )
			p[-1] = ' ' ;
	}
	return(0) ;
}

// print formatted line for permuted index
// two tab-separated fields
//    1st is sort key
//    2nd is printable line
// pipe it through something like
//   sort -F | awk -F '\t' '{print $2}'
// to get final output

print_line( char *before, char *word, char *after, char *tag)
{
	int i , x, y, z ;
/*
	printf("%s\t%s\t%s\t%s\n", before, word, after, tag) ;
*/
	if( list_word(word) )
		return ;
	x = strlen(before) ;
	y = strlen(word) ;
	z = strlen(after) ;
	// put in sortable field
	// strip out with awk after sorting
	printf("%s %s\t", word, after) ;
	// shorten before string to fit field
	for( ; x > 30 ; x-- )
		before++ ;
	printf("%30s", before) ;
	// print keyword, html tagged
	printf("  %s%s</a>  ", tag, word) ;
	// padding, outside tag
	for( ; y < 18 ; y++ )
		putchar(' ') ;
	if( z )
		printf("%s", after) ;
	printf("\n") ;
}

// avoid indexing on common English words

char *list[] = {
		"the", "of", "a", "an", "to", "and",  "or", "if", "for", "at",
		"am", "is", "are", "was", "were", "have", "has", "had", "be", "been",
		"on", "some", "with", "any", "into", "as", "by", "in", "out",
		"that", "then", "this", "that", "than", "these", "those",
		"he", "his", "him", "she", "her", "hers", "it", "its",
		"&", "", "+", "-", "=", "--", "<", ">", "<=", ">=",
		"!", "?", "#", "$", "%", "/", "\\", "\"", "\'",
		NULL
		} ;
// interrogative words like "how" and "where" deliberately left out of
// above list because users might want to search for "how to..." etc.

// return 1 if word in list, else 0
// case-insensitive comparison

list_word( char *p )
{
	char **z ;
	for( z = list ; *z != NULL ; z++ )
		if( ! strcasecmp( p, *z ) )
			return 1 ;
	return 0 ;
}

