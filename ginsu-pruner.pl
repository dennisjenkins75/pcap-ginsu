#!/usr/bin/perl -wT

# Prunes older ginsu 'queue' files from disk.

# Usage:  Add to root's crontab as follows (edit to taste):
# 10 0 * * * /usr/local/bin/ginsu-pruner.pl -d 14 -f 100000 | sh

use strict;
use warnings;
use diagnostics;
use Getopt::Long;
use POSIX;
use Filesys::Df;
use File::stat;

my $opt_queue_dir = undef;
my $opt_min_free = undef;
my $opt_verbose = 0;

######
######	Step #1, Process arguments.
######

GetOptions (
	"d=s" => \$opt_queue_dir,
	"f=i" => \$opt_min_free,
	"v+" => \$opt_verbose,
);

if (!defined $opt_queue_dir || !defined $opt_min_free) {
	print STDERR "Usage: -d dir -f min_free_megs [-v]\n";
	exit (-1);
}

######
######	Step #2, Get free space for filesystem holding the queue dir.
######

# Get file-system block size.
my $blksize = (stat($opt_queue_dir))->blksize;
die "Can't get filesystem block size.\n" if ((!defined $blksize) || ($blksize < 1));

# Convert from megabytes to block cound.
$opt_min_free = ($opt_min_free * 1024) / ($blksize / 1024);	


my $df_ref = df ($opt_queue_dir, $blksize);
my $free_blocks = int($df_ref->{bavail});

print "# blksize      = $blksize\n" if ($opt_verbose);
print "# free blocks  = $free_blocks\n" if ($opt_verbose);
print "# min free     = $opt_min_free\n" if ($opt_verbose);

######
######	Step #3, Enum all files in directory.
######

my %fsizes;
my %ftimes;

opendir (DIR, $opt_queue_dir) or die "opendir ($opt_queue_dir) failed.\n";
while (my $fname = readdir (DIR)) {
	next unless ($fname =~ /^(\d\d\d\d\d\d\d\d-\d\d\d\d\d\d\.\d\d\d\d\d\d)\.(.*)\.pcap/);
	my $statbuf = stat ("$opt_queue_dir/$fname");

	next unless (defined $statbuf);
	next unless (defined $statbuf->blocks);		# Count of "512" byte "blocks".
	next unless (defined $statbuf->mtime);		# File last modification time.

	$fsizes{$fname} = int(($statbuf->blocks * 512 + $blksize - 1) / $blksize);
	$ftimes{$fname} = $statbuf->mtime;
}
closedir (DIR);

######
######	Step #4, Delete files until we've got enough free-space
######

my $needed = $opt_min_free - $free_blocks;
print "# needed       = $needed\n" if ($opt_verbose);

exit (0) if ($needed <= 0);

foreach my $fname (sort {$ftimes{$a} <=> $ftimes{$b}} (keys %ftimes)) {
	print "rm -f $opt_queue_dir/$fname\n";

	$needed -= $fsizes{$fname};
	last if ($needed <= 0);
}
