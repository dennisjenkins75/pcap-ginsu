# pcap-ginsu
Ethernet packet file recorder, slicer, dicer.

"pcap-ginsu" implements three programs:

1. ginsu-capture: daemon that records ethernet traffic to files on disk.
1. ginsu-slicer: tool to split, slice and merge PCAP files into other PCAP files based on a set of user-supplied filters and rules.
1. ginsu-pruner: Perl script that deletes other PCAP files, maintaining a minimum amount of free disk space (hint: run from cron hourly or daily).

Requires these Gentoo Linux packages:

1. >=net-libs/libnids-1.18
1. >=dev-libs/confuse-2.6-r3
1. >=net-libs/libpcap-1.0.0-r2
1. >=net-libs/libpcapnav-0.7

TODO:

1. Convert to use "autoconf".  Right now the build script is simple and	"works on my box" (Gentoo Linux).
1. Code cleanup.  It's ugly.  Really ugly.
1. Create official Gentoo .ebuild and get into public repository.
1. Better documentation.

Usage:

	make && sudo make install

	create directory to hold captured files "mkdir /ginsu", for example.

	edit /etc/conf.d/ginsu-capture

	"/etc/init.d/ginsu-capture start"

	Observe: "find /ginsu -ls"
	Every 4 minutes, or 16MB, ginsu-capture will rotate the capture file from
	the "live" directory into the "queue" directory.

	Schedule the pruner in crontab:
		crontab -u root -e
		10 0 * * * /usr/local/bin/ginsu-pruner.pl -d 14 -f 100000 | sh

	When you want to slice + dice your packets, create a config file that
	defines how to slice up the queued packet files.  Samples are provided
	(sample.conf).

	ginsu-slicer -c ./sample.conf -D /tmp /ginsu/queue/*.pcap
