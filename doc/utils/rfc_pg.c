/*
 *  $Header: /var/cvsroot/strongswan/doc/utils/rfc_pg.c,v 1.1 2004/03/15 20:35:24 as Exp $
 *
 * from 2-nroff.template file.
 *
 *  Remove N lines following any line that contains a form feed (^L).
 *  (Why can't this be done with awk or sed?)
 *
 *  OPTION:
 *	-n#	Number of lines to delete following each ^L (0 default).
 * $Log: rfc_pg.c,v $
 * Revision 1.1  2004/03/15 20:35:24  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.1  2002/07/23 18:42:43  mcr
 * 	required utility from IETF to help with formatting of drafts.
 *
 */
#include <stdio.h>

#define FORM_FEED	'\f'
#define OPTION		"n:N:"		/* for getopt() */

extern char *optarg;
extern int optind;

main(argc, argv)
int	argc;
char	*argv[];
{
  int	c,				/* next input char */
	nlines = 0;			/* lines to delete after ^L */
  void	print_and_delete();		/* print line starting with ^L,
					   then delete N lines */

/*********************** Process option (-nlines) ***********************/

  while ((c = getopt(argc, argv, OPTION)) != EOF)
    switch(c)
    {
      case 'n' :
      case 'N' :  nlines = atoi(optarg);
		  break;
    }
/************************* READ AND PROCESS CHARS **********************/

  while ((c = getchar()) != EOF)
    if (c == FORM_FEED)
      print_and_delete(nlines);		/* remove N lines after this one */
    else
      putchar(c);			/* we write the form feed */
  exit(0);
}


/*
 *  Print rest of line, then delete next N lines.
 */
void print_and_delete(n)
int  n;					/* nbr of lines to delete */
{
  int	c,				/* next input char */
	cntr = 0;			/* count of deleted lines */

  while ((c = getchar()) != '\n')	/* finish current line */
    putchar(c);
  putchar('\n');			/* write the last CR */
  putchar(FORM_FEED);

  for ( ; cntr < n; cntr++)
    while ((c = getchar()) != '\n')
      if (c == EOF)
	exit(0);			/* exit on EOF */
  putchar(c);				/* write that last CR */
}

