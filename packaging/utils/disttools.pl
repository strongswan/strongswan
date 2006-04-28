#!/usr/bin/perl

#
# $Id: disttools.pl,v 1.1 2004/03/15 20:35:27 as Exp $
#
# $Log: disttools.pl,v $
# Revision 1.1  2004/03/15 20:35:27  as
# added files from freeswan-2.04-x509-1.5.3
#
# Revision 1.13  2003/06/17 22:30:06  build
# 	adjusted userid to pick
# 	use key that is offline.
#
# Revision 1.12  2002/09/30 16:02:17  mcr
# 	added handling for date stamp.
#
# Revision 1.11  2002/08/30 01:30:25  mcr
# 	changed code to write maintain local copy of FTP site,
# 	and rsync things up when needed.
#
# Revision 1.10  2002/07/29 05:13:33  mcr
# 	append .gz to patch files before they are signed.
#
# Revision 1.9  2002/07/29 04:02:21  mcr
# 	removed errant ) from tar copy line.
#
# Revision 1.8  2002/07/29 03:57:59  mcr
# 	produce kernel patches as part of the snapshots, candidates
# 	and releases.
#
# Revision 1.7  2002/06/07 18:23:49  mcr
# 	adjusted sendfiles to use tar to copy rather than scp.
# 	mkcand now prints usage if you don't give it enough arguments.
# 	It also now updates the "CANDIDATE" symlink.
# 	mksnap properly quotes the wildcards in the -name for find.
#
# Revision 1.6  2002/06/03 03:10:58  mcr
# 	"upload" now takes argument to indicate name to
# 	install/upload for the symlink.
#
# Revision 1.5  2002/06/03 02:19:40  mcr
# 	fixed bug in datelettername() - y/sed was not applied to $let,
# 	but to $_.
#
# Revision 1.4  2002/06/03 02:14:16  mcr
# 	die statements are now numbered for easier backtracking.
# 	candidate checks are now done if $candidate arg=1: edit README
# 	and CHANGES file for mkcand.
#
# Revision 1.3  2002/05/30 23:24:22  mcr
# 	working "mksnap" and disttools.pl.
#
# Revision 1.2  2002/05/30 22:20:56  mcr
# 	initial debugging done.
#
# Revision 1.1  2002/05/30 21:24:00  mcr
# 	perl-ified mksnap.
#
#

@supportedkernels=("2.0", "2.2", "2.4");

sub nicesystem {
  if($debug) {
    print STDERR "System: ",join(' ',@_)."\n";
  }
  system(@_);
  if($? == 0) {
    return 1;
  } else {
    return 0;
  }
}

sub kpatchname {
  local($pkgname, $ver)=@_;
  local($name);

  $name = $pkgname.".k".$ver.".patch";
  return $name;
}
  

sub datelettername {
  @MoY = ('jan','feb','mar','apr','may','jun',
	  'jul','aug','sep','oct','nov','dec');

  $letters="abcdefghjklmnpqrstuvwxyz";

  ($sec, $min, $hour, $mday, $mon, $year) = gmtime(time);
	
  $let=substr($letters, $hour-1, 1);
  if($min >= 30) {
    $let =~ y/a-z/A-Z/;
  }

  if($year < 1900) {
    $year += 1900;
  }
  
  $ver=sprintf("%04d%s%02d%s", $year, $MoY[$mon], $mday, $let);
  $ver;
}

sub snapname {
  local($prefix)=@_;
  $snapname=$prefix.&datelettername;
  $snapname;
}

sub suckvars {
  $envvar=$ENV{'HOME'}."/freeswan-regress-env.sh";

  if(-f $envvar) {
    
    open(SHVARS, $envvar) || die "001:  Can not open $envvar: $!\n";
    while(<SHVARS>) {
      chop;
      next if (/^\#/);

      if(/(\S+)\=(\S+)/) {
	$var=$1;
	$value=$2;

	$ENV{$var}=$value;
      }
    }
    close(SHVARS);
  }
}
      
sub defvar {
  local($var,$value)=@_;
  
  if(!defined($ENV{$var})) {
    $ENV{$var}=$value;
  }
}

sub defvars {
  &defvar('BTMP', '/btmp');
  if($ENV{'DEBUGFREESWANDIST'}) {
    $debug=$ENV{'DEBUGFREESWANDIST'};
  }
}

sub setuppgp {
  local($lastrel)=@_;

  $lastrel =~ y/\./\_/;

  $ENV{'PGPPATH'}=$ENV{'SNAPSHOTSIGDIR'}."/BASEPRE$lastrel";
  $ENV{'PGPNAME'}="build+snap".$lastrel."\@freeswan.org";
}

sub dopgpsig {
  local($pkgname)=@_;

  local($tarfile);
  $tarfile=$pkgname.".tar";
  
  $userid=$ENV{'PGPNAME'};
  &nicesystem("pgp -sba $tarfile.gz -u $userid -o $tarfile.gz.sig") || die "002:  PGP failed: $?\n";
  &nicesystem("chmod a+r $tarfile.gz.sig");

  foreach $ver (@supportedkernels) {
    $file=&kpatchname($pkgname,$ver).".gz";
    &nicesystem("pgp -sba $file -u $userid -o $file.sig") || die "002:  PGP failed: $?\n";
    &nicesystem("chmod a+r $file.sig");
  }
}
  

# this function now does two things: 
#   1) makes the tar file of old
#   2) makes the kernel patch file of new.
#

sub makedisttarfile {
  local($tmpdir, $pkgname, $vername, $dirname, $date, $relopt, $candidate)=@_;
  local($file);

  &nicesystem("mkdir -p $tmpdir") || die "003:  Can not mkdir $tmpdir\n";
  chdir($tmpdir) || die "004:  makedisttarfile: Can not chdir to $tmpdir\n";

  # nuke anything that was there before
  &nicesystem("rm -rf $dirname");

  if(defined($date) && $date ne '') {
    $minusD="-D \"${date}\"";
  }

  print "cvs -Q export $minusD ${relopt} -d ${dirname} freeswan\n";

  &nicesystem("cvs -Q export $minusD ${relopt} -d ${dirname} freeswan") || die "005:  CVS failed!\n";

  chdir($dirname) || die "006:  Can not chdir to $dirname\n";

  open(VERSIONFILE, ">Makefile.ver") || die "007:  failed to open Makefile.ver\n";
  print VERSIONFILE "IPSECVERSION=".$vername."\n";
  close(VERSIONFILE);

  if($candidate) {
    open(README, "README")     || die "008:  Can not edit README: $!\n";
    $nreadme="README.$$";
    open(NREADME, ">$nreadme") || die "009:  Can not write README: $!\n";
    $lines=1;
    while(<README>) {
      if($lines == 1) {
	s/xxx/$vername/;
      }
#      if(/^---$/) {
#	print STDERR "README not ready, run prepcand first\n";
#	die;
#     }
      $lines++;
      print NREADME;
    }
    close(NREADME);
    close(README);
    unlink("README") || die "010:  Can not remove README: $!\n";
    rename("$nreadme", "README") || die "011:  Can not rename $nreadme to README: $!\n";

    # now edit CHANGES file
    open(CHANGES, "CHANGES")     || die "012:  Can not edit README: $!\n";
    $nchanges="CHANGES.$$";
    open(NCHANGES,">$nchanges") || die "013:  Can not write README: $!\n";
    $lines=1;
    while(<CHANGES>) {
      if($lines == 1) {
	if(/since last release/) {
	  die "CHANGES not ready, run prepcand first";
	}
	s/xxx/$vername/;
      }
      $lines++;
      print NCHANGES;
    }
    close(NCHANGES);
    close(CHANGES);
    unlink("CHANGES") || die "014:  Can not remove CHANGES: $!\n";
    rename("$nchanges", "CHANGES") || die "015:  Can not rename $nreadme to README: $!\n";
  }
  
  &nicesystem("make -f dtrmakefile -s snapready") || die "016:  failed to make snapshot ready for distribution: $?\n";
  
  chdir("..") || die "017:  failed to go to parent dir: $!\n";

  unlink("$pkgname.tar");
  unlink("$pkgname.tar.gz");
  unlink("$pkgname.tar.gz.md5");
  
  &nicesystem("tar -cf $pkgname.tar $dirname") || die "018:  Failed to tar file: $?\n";

  # make the kernelpatch for each of 2.0, 2.2, and 2.4.
  foreach $ver (@supportedkernels) {
    $file=&kpatchname($pkgname,$ver);
    &nicesystem("make -C $dirname kernelpatch$ver >$file");
    &nicesystem("gzip -9 $file");
  }

  &nicesystem("rm -rf $dirname") || warn "failed to cleanup $dirname\n";

  &nicesystem("gzip -9 $pkgname.tar") || die "019:  gzip died: $?\n";

  &nicesystem("ls -l $pkgname.tar.gz");

  &nicesystem("md5sum $pkgname.tar.gz >$pkgname.tar.gz.md5");
  &nicesystem("chmod a+r $pkgname.tar.gz");
}

sub sendfiles {
  local(@thefiles)=@_;

  local($file, $localroot);
  
if($ENV{'DEV_DIR'}) { $localroot=$ENV{'DEV_DIR'}; } else {  $localroot=$ENV{'LOCAL_ARCHIVE'}; }

  foreach $file (@thefiles) {
    $dir=$file;
    if(!($dir =~ s,(.*)/([^/]*),\1,)) {
      $dir=".";
    } else {
      $file=$2;
    }

    &nicesystem("tar -C $dir -c -f - $file | tar -C ${localroot} -x -f -");
  }
}


sub remotecmd {
  local($cmd)=@_;

  $distuser=$ENV{'DISTUSER'};
  $disthost=$ENV{'DISTHOST'};
  $distdir =$ENV{'DISTDIR'};
  $ssh     =$ENV{'ssh'};

  &nicesystem("$ssh -l $distuser $disthost '$cmd'");
}


sub upload {
  local($pkgname, $symlinkname)=@_;

  local($localroot);
  
if($ENV{'DEV_DIR'}) { $localroot=$ENV{'DEV_DIR'}; } else {  $localroot=$ENV{'LOCAL_ARCHIVE'}; }

  &sendfiles("$pkgname.tar.gz",
	     "$pkgname.tar.gz.sig",
	     "$pkgname.tar.gz.md5");

  foreach $ver (@supportedkernels) {
    $file=&kpatchname($pkgname,$ver).".gz";
    &sendfiles($file, "$file.sig");
  }

  if(defined($symlinkname)) {
    &sendfiles($symlinkname.".tar.gz.md5");
    &nicesystem("cd $localroot && ln -f -s $pkgname.tar.gz $symlinkname.tar.gz && ln -f -s $pkgname.tar.gz.sig $symlinkname.tar.gz.sig");

    foreach $ver (@supportedkernels) {
      $file=&kpatchname($pkgname,$ver);
      $newname=&kpatchname($symlinkname,$ver);
      &nicesystem("cd $localroot && ln -f -s $file.gz $newname.gz && ln -f -s $file.gz.sig $newname.gz.sig");
    }
    
  }
}

sub upsync {
  
  local($localroot, $distuser, $disthost, $distdir, $spoolhost, $spooluser);
  local($masterhost, $masteruser, $masterdir);

  $localroot=$ENV{'LOCAL_ARCHIVE'};
  $distuser=$ENV{'DISTUSER'};
  $disthost=$ENV{'DISTHOST'};
  $distdir =$ENV{'DISTDIR'};
  $ssh     =$ENV{'ssh'};
  $masterhost = $ENV{'MASTERHOST'};
  $masteruser = $ENV{'MASTERUSER'};
  $masterdir = $ENV{'MASTERDIR'};

  # sync stuff to distribution site.
  &nicesystem("rsync -e $ssh -r --delete -a -v -c $localroot/ $masteruser\@$masterhost:$masterdir/");

  # sync stuff to xs4all site.
  &nicesystem(print "rsync -e $ssh -r --delete -a -v -c $localroot/ $distuser\@$disthost:$distdir/");
  &nicesystem("rsync -e $ssh -r --delete -a -v -c $localroot/ $distuser\@$disthost:$distdir/");

}

1;

