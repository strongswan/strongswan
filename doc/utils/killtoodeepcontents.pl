#!/usr/bin/perl

$toc=0;
$memo=0;

while(<>) {
  if(0 && /^Status of this Memo/) {
    $memo=1;
    print;
    next;
  }
    
  if(/^Table of Contents/) {
    print ".bp\n";
    $toc=1;
    print;
    next;
  }
  
  if(!$toc && !$memo) {
    print;
    next;
  }

  if($toc) {
    if(/^[0-9]*\.[0-9]*\.[0-9]* / ||
#       /^[0-9]*\.[0-9]* / ||
       /^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]* /) {
      next;
    }

    if(/^14./) {
      $toc=0;
    }
    if(/^\.bp/) {
      next;
    }
    print;
  }

  if($memo) {
    if(/^\.bp/) {
      next;
    }
    
    if(/^Copyright Notice/) {
      print ".fi\n";
      print "This memo provides information for the Internet community.  It does\n";
      print "not specify an Internet standard of any kind.  Distribution of this\n";
      print "memo is unlimited.\n";
      print "\n.ti 0\n";

      print;

      $memo=0;
      next;
    }
  }
}
