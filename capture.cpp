/*	ginsu/capture.c

	Copyright, 2015, Dennis Jenkins

Concurrently captures ethernet packets on multiple interfaces.  Saves packets
to disk and flushes / rotates files frequently.  Designed to be the 'front-end'
to "ginsu".

Immediately after acquiring the capture sockets this program will drop
root privledges and run as the user "tcpdump".

Currently does not run in a chroot jail (on wish list).

Compiles under Gentoo Linux (2008.0, /etc/release = 1.12.11.1)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pcapnav.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <time.h>

#define MAX_DEVICES 16

#define DISK_CHECK_INTERVAL		(16 * 1024 * 1024)
#define DEFAULT_FLUSH_INTERVAL		(60 * 5)
#define DEFAULT_MAX_CAP_SIZE_MB		(256)
#define DEFAULT_MIN_DISK_FREE_MB	(2048)
#define DEFAULT_RUNAS_USER		"tcpdump"
#define DEFAULT_RUNAS_GROUP		"tcpdump"
#define DEFAULT_PID_FILE		"/run/ginsu-capture.pid"
#define DEFAULT_PACKET_DIR		"/ginsu"
#define DEFAULT_LOG_FILE		"/var/log/ginsu-capture.log"


// Set via command line options.
static int _daemon = 0;
static int verbose = 0;
static int flush_interval = DEFAULT_FLUSH_INTERVAL;
static int max_cap_size_mb = DEFAULT_MAX_CAP_SIZE_MB;
static int min_disk_free_mb = DEFAULT_MIN_DISK_FREE_MB;
static char *packet_dir = DEFAULT_PACKET_DIR;
static char *pid_file = DEFAULT_PID_FILE;
static char *log_file = DEFAULT_LOG_FILE;
static char *runas_user = DEFAULT_RUNAS_USER;
static char *runas_group = DEFAULT_RUNAS_GROUP;
static char *g_bpf = NULL;

// Internal.
static const int pcap_timeout = 2500;
static volatile int my_shutdown = 0;
static uid_t runas_uid = -1;
static gid_t runas_gid = -1;
static int dev_count = 0;

struct worker
{
	pcap_t		*pcap;
	int		pcap_fd;
	const char	*dev_name;
	struct bpf_program	*bpf;
	int		pkt_count;
	int		dropping;
	int		next_disk_check;
	pcap_dumper_t	*dumper;
	time_t		ts_open;
	char		base_name[PATH_MAX];
};

static struct worker workers[MAX_DEVICES];
static const char *dev_list[MAX_DEVICES];

static void	open_dump_file (struct worker *w)
{
	char	tmp_file[PATH_MAX];
	char	ts[32];
	struct	timeval tv;
	struct	tm *tm = NULL;

	assert (!w->dumper);
	assert (w->pcap);

	gettimeofday (&tv, NULL);
	tm = localtime ((const time_t*)&tv.tv_sec);
	strftime (ts, sizeof(ts), "%Y%m%d-%H%M%S", tm);
	snprintf (w->base_name, sizeof(w->base_name), "%s.%06lu.%s", ts, tv.tv_usec, w->dev_name);
	snprintf (tmp_file, sizeof(tmp_file), "%s/live/%s.pcap", packet_dir, w->base_name);
	w->dumper = pcapnav_dump_open (w->pcap, tmp_file, PCAPNAV_DUMP_APPEND_SAFE);

	if (!w->dumper)
	{
		fprintf (stderr, "failed to open '%s'\n", tmp_file);
		pcap_breakloop (w->pcap);
	}

	w->ts_open = time(NULL);
}

static void	close_dump_file (struct worker *w)
{
	char final[PATH_MAX];
	char tmp_file[PATH_MAX];

	assert (w->dumper);
	assert (w->pcap);

	pcap_dump_close (w->dumper);
	w->dumper = NULL;

	snprintf (tmp_file, sizeof(tmp_file), "%s/live/%s.pcap", packet_dir, w->base_name);
	snprintf (final, sizeof(final), "%s/queue/%s.pcap", packet_dir, w->base_name);

// FIXME: Hopefully we're not clobbering a destination file...
	rename (tmp_file, final);

	w->base_name[0] = 0;
}

static void	callback (u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	struct worker *w = (struct worker*)args;
	w->pkt_count++;

// If we don't have an open dump file, open one now.
	if (!w->dumper)
	{
		open_dump_file (w);
	}

	if (!w->dumper)		// "open" could have failed.
	{
		return;
	}

// Do we have enough disk space?
// Check disk free space only periodically.  The check itself is expensive (lots of syscalls).
	w->next_disk_check += hdr->len;
	if (w->dropping || ((max_cap_size_mb > 0) && (w->next_disk_check > DISK_CHECK_INTERVAL)))
	{
		struct statvfs statvfs;

		w->next_disk_check = 0;

		if (-1 == fstatvfs (fileno(pcap_dump_file(w->dumper)), &statvfs))
		{
			perror ("statvfs");
			close_dump_file (w);
			return;
		}

		if (statvfs.f_bavail < (1024LLU * 1024 * min_disk_free_mb) / statvfs.f_bsize)
		{
			if (!w->dropping)
			{
				fprintf (stderr, "Low disk space.  Dropping for %s\n", w->dev_name);
			}

			w->dropping = 1;
			return;
		}

		if (w->dropping)
		{
			fprintf (stderr, "Available disk space, no longer dropping for %s\n", w->dev_name);
		}

		w->dropping = 0;
	}

	pcap_dump ((u_char*)w->dumper, hdr, pkt);

	if (my_shutdown || (pcap_dump_ftell (w->dumper) > (max_cap_size_mb * 1024 * 1024)))
	{
		close_dump_file (w);
	}

	if (my_shutdown)
	{
		pcap_breakloop (w->pcap);
	}
}

static int sig_list[] =
{ SIGHUP, SIGINT, SIGTERM, 0 };

static void	handler_shutdown (int n)
{
	int	i;

// Let next signal kill process via default handler.
	for (i = 0; sig_list[i]; i++)
	{
		signal (sig_list[i], SIG_DFL);
	}

	my_shutdown = 1;
}

static const char usage_txt[] =
	"Usage: %s [opts]\n"
	"-i iface1[,iface2[,iface3...]]   (no default)\n"
	"-t flush interval (s)  (default = %d)\n"
	"-s max pcap file (MB)  (default = %d)\n"
	"-m min disk free (MB)  (default = %d)\n"
	"-f \"bpf expression\"  (default = none)\n"
	"-u runas user          (default = '%s')\n"
	"-g runas group         (default = '%s')\n"
	"-p pid file            (default = '%s')\n"
	"-D packet dir          (default = '%s')\n"
	"-d become daemon       (default = no)\n"
	"-l log file            (default = '%s')\n"
	"-v verbose             (default = no)\n";

static void usage (const char *prog)
{
	fprintf (stderr, usage_txt, prog,
		DEFAULT_FLUSH_INTERVAL, DEFAULT_MAX_CAP_SIZE_MB, DEFAULT_MIN_DISK_FREE_MB,
		DEFAULT_RUNAS_USER, DEFAULT_RUNAS_GROUP,
		DEFAULT_PID_FILE, DEFAULT_PACKET_DIR, DEFAULT_LOG_FILE);
	exit (-1);
}

int	main (int argc, char *argv[])
{
	fd_set		set;
	struct timeval	timeout = {0};
	int		r = 0;
	int		i = 0;
	int		max_fd = 0;
	int		fd = 0;
	FILE		*fp_pid = NULL;
	struct worker	*w = NULL;
	time_t		ts_flush = 0;
	char		errbuf[PCAP_ERRBUF_SIZE];
	char		*iface_list = NULL;
	char		*p = NULL;
	struct passwd	*pwd = NULL;
	struct group	*grp = NULL;
	char		*endptr = NULL;

	memset (&workers, 0, sizeof(workers));
	memset (&dev_list, 0, sizeof(dev_list));

	while (-1 != (i = getopt (argc, argv, "vdi:t:s:m:f:u:g:p:D:l:")))
	{
		switch (i)
		{
			case 'i':
				iface_list = optarg;
				break;

			case 't':
				flush_interval = atoi (optarg);
				break;

			case 's':
				max_cap_size_mb = atoi (optarg);
				break;

			case 'm':
				min_disk_free_mb = atoi (optarg);
				break;

			case 'f':
				g_bpf = optarg;
				break;

			case 'v':
				verbose++;
				break;

			case 'd':
				_daemon++;
				break;

			case 'u':
				runas_user = optarg;
				break;

			case 'g':
				runas_group = optarg;
				break;

			case 'p':
				pid_file = optarg;
				break;

			case 'D':
				packet_dir = optarg;
				break;

			case 'l':
				log_file = optarg;
				break;

			case 'h':
			case '?':
				usage (argv[0]);
				break;
		}
	}

// split "iface_list" into "dev_list"
	if (NULL != (p = strtok (iface_list, ",")))
	{
		dev_count = 0;
		while (p && (dev_count < MAX_DEVICES))
		{
			dev_list[dev_count++] = p;
			p = strtok (NULL, ",");
		}
	}

	if (!dev_count)
	{
		fprintf (stderr, "You must specify at least one interface via '-i ethxxx'\n");
		usage (argv[0]);
	}

// Resolve '-u' arg, if any.
	runas_uid = strtol (runas_user, &endptr, 10);		// Allow a numeric string?
	if (*endptr)
	{
		if (NULL == (pwd = getpwnam (runas_user)))
		{
			fprintf (stderr, "Unknown user account: '%s'.\n", runas_user);
			exit (EXIT_FAILURE);
		}
		runas_uid = pwd->pw_uid;
		runas_gid = pwd->pw_gid;
	}

	runas_gid = strtol (runas_group, &endptr, 10);
	if (*endptr)
	{
		if (NULL == (grp = getgrnam (runas_group)))
		{
			fprintf (stderr, "Unknown group: '%s'\n", runas_group);
			exit (EXIT_FAILURE);
		}
		runas_gid = grp->gr_gid;
	}

	if (getuid())
	{
		fprintf (stderr, "%s must be started as 'root'.\n", argv[0]);
		exit (EXIT_FAILURE);
	}

// If we are a daemon, enter daemon mode
	if (_daemon)
	{
// Step 1, have the parent exit immediately.
		if (fork()) { exit (0); }

// Step 2, create a new session group.
		setsid();

// Step 3, fork again, so that the session group leader can exit.
// Note: We will never be able to regain control of a terminal.
		if (fork()) { exit (0); }

// Step 4, do not keep a lock on the 'cwd'.
		if (-1 == chdir ("/")) {
			exit (-1);
		}

// Step 5, deny 'other' access to any files that we create (by default).
		umask(007);

// Step 6, close all descriptors that belonged to our parent.
		close(0);
		close(1);
		close(2);

// Step 7, reopen those descriptors for our own use.
		fd = open("/dev/null", O_RDONLY);
		assert(fd == 0);

		fd = open(log_file, O_WRONLY | O_APPEND | O_CREAT, 0644);
		assert(fd == 1);
//		fchmod(fd, 0644);

		fd = dup2(1, 2);
		assert(fd == 2);
	}
	else
	{
		umask(007);
	}

	if (verbose)
	{
		printf ("%s pid = %d\n", argv[0], getpid());
	}

	for (i = 0; sig_list[i]; i++)
	{
		signal (sig_list[i], handler_shutdown);
	}

// If we are a daemon our PID has changed twice since when we were spawned.
// Create the PID file.

	if (-1 == (fd = open (pid_file, O_CLOEXEC | O_CREAT | O_EXCL | O_NOATIME | O_NOFOLLOW | O_RDWR, 0644)))
	{
		fprintf (stderr, "Failed to create pid file: %s\n", pid_file);
		perror ("open");
		exit (EXIT_FAILURE);
	}

// Need to chown the PID file, or we won't be able to nuke it once we 'setuid'.
	if (-1 == fchown (fd, runas_uid, runas_gid))
	{
		fprintf (stderr, "Failed to set ownership of pid file ('%s') to '%d:%d'\n", pid_file, runas_uid, runas_gid);
		perror ("fchown");
		exit (EXIT_FAILURE);
	}

	if (-1 == fchmod (fd, 0644))
	{
		fprintf (stderr, "Failed to fchmod() pid file ('%s')\n", pid_file);
		perror ("fchmod");
		exit (EXIT_FAILURE);
	}

	if (NULL == (fp_pid = fdopen (fd, "wt")))
	{
		perror ("fdopen");
		close (fd);
		exit (EXIT_FAILURE);
	}

	fprintf (fp_pid, "%d\n", getpid());
	fclose (fp_pid);
	fp_pid = NULL;
	fd = -1;

// Open capture files before we surrender our privlidges.
	for (w = workers, i = 0; i < dev_count; ++i)
	{
		w->dev_name = NULL;
		w->pcap = NULL;
		w->pcap_fd = 0;
		w->bpf = NULL;
		w->pkt_count = 0;
		w->next_disk_check = 0;
		w->dumper = NULL;
		w->base_name[0] = 0;

		if (NULL == (w->pcap = pcap_open_live (dev_list[i], BUFSIZ, 1, pcap_timeout, errbuf)))
		{
			fprintf (stderr, "pcap_open_live (%s) failed: %s\n", dev_list[i], errbuf);
			continue;
		}

		if (-1 == (w->pcap_fd = pcap_get_selectable_fd (w->pcap)))
		{
			fprintf (stderr, "pcap_get_selectable_fd (%s) failed.\n", dev_list[i]);
			pcap_close (w->pcap);
			w->pcap = NULL;
			w->pcap_fd = 0;
			continue;
		}
// printf ("bpf = %p\n", g_bpf);
		if (g_bpf)
		{
			if (NULL == (w->bpf = (struct bpf_program*) malloc (sizeof (struct bpf_program))))
			{
				fprintf (stderr, "malloc %lu failed\n", sizeof (struct bpf_program));
				perror ("malloc");
				w->pcap = NULL;
				w->pcap_fd = 0;
				continue;
			}

			if (-1 == pcap_compile (w->pcap, w->bpf, g_bpf, 1, 0))
			{
				fprintf (stderr, "BPF syntax error:\n%s\n", pcap_geterr (w->pcap));
				free (w->bpf);
				w->bpf = NULL;
				goto bpf_done;
			}

			if (-1 == pcap_setfilter (w->pcap, w->bpf))
			{
				fprintf (stderr, "pcap_setfilter() failed:\n%s\n",  pcap_geterr (w->pcap));
				free (w->bpf);
				w->bpf = NULL;
				goto bpf_done;
			}

			if (verbose)
			{
				printf ("bpf set: '%s'\n", g_bpf);
			}
		}
bpf_done:

		w->dev_name = dev_list[i];
		++w;
	}

// Change group first (can't change it after changing user).
	if (runas_gid)
	{
		if (-1 == setgid (runas_gid))
		{
			fprintf (stderr, "setgid (%d) failed.\n", runas_gid);
			perror ("setgid");
			unlink (pid_file);
			exit (EXIT_FAILURE);
		}
	}

	if (runas_uid)
	{
		if (-1 == setuid (runas_uid))
		{
			fprintf (stderr, "setuid (%d) failed.\n", runas_uid);
			perror ("setuid");
			unlink (pid_file);
			exit (EXIT_FAILURE);
		}
	}

// Multiplex capture devices until we fail or get SIGINT.
	while (!my_shutdown)
	{
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		FD_ZERO (&set);

		for (max_fd = 0, w = workers; w->pcap; ++w)
		{
			FD_SET (w->pcap_fd, &set);
			max_fd = (w->pcap_fd > max_fd) ? w->pcap_fd : max_fd;
		}

		if (-1 == (r = select (max_fd + 1, &set, NULL, NULL, &timeout)))
		{
			perror ("select");
			break;
		}

		ts_flush = time(NULL);

		for (w = workers; w->pcap; ++w)
		{
			if (FD_ISSET (w->pcap_fd, &set))
			{
				if (-1 == (r = pcap_dispatch (w->pcap, 0, callback, (u_char*)w)))
				{
					fprintf (stderr, "pcap_dispatch (%s) failed: %s\n", w->dev_name, pcap_geterr (w->pcap));
				}
			}

			if (w->dumper && (w->ts_open + flush_interval < ts_flush) && w->pkt_count)
			{
				close_dump_file (w);
			}
		}
	}

	if (verbose)
	{
		printf ("exiting...\n");
	}

	for (w = workers; w->pcap; ++w)
	{
		if (w->dumper)
		{
			close_dump_file (w);
		}

		pcap_close (w->pcap);
	}

	if (-1 == unlink (pid_file))
	{
		perror ("unlink");
	}

	return 0;
}
