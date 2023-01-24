/*	ginsu/ginsu.c

	Processes packets saved by 'ginsu-capture'.  Splits pcap files by
	src/dest tuples for further processing.
*/

#include "ginsu.h"

// Set via command line options.
static int verbose = 0;
static char *g_pszDestDir = NULL;
static off64_t g_nUnsorted = 0;
static off64_t g_nTotalPackets = 0;
static off64_t g_nTotalBytes = 0;
static size_t MAX_DUMP_SIZE = 64 * 1024 * 1024;
static size_t pcap_buff_size = 1024 * 1024;
static bool g_bProgressBar = true;
static int g_nReportSort = 0;
static time_t g_nStart = (time_t)0;
static time_t g_nStop = (time_t)0x7fffffff;

struct ReportItem
{
	const cfg_slice *pSlice;

	ReportItem (const cfg_slice *p) : pSlice(p) {}
};

// Reverses order....
static inline bool operator< (const ReportItem &a, const ReportItem &b)
{
	if (g_nReportSort)
	{
		return a.pSlice->pkt_count > b.pSlice->pkt_count;
	}

	return a.pSlice->pkt_bytes > b.pSlice->pkt_bytes;
}

static inline float perc (off64_t x, off64_t t)
{
	return 100.0f * ((double)x / (double)t);
}

static char*	format_size (char *dest, int destlen, off64_t value)
{
	std::vector<unsigned int> vParts;
	char *p = dest;
	char *e = p + destlen;
	static const off64_t k = 1000;

	while (value > 0)
	{
		unsigned int x = static_cast<unsigned int>(value % k);
		vParts.push_back (x);
		value /= k;
	}

	std::vector<unsigned int>::reverse_iterator iter;
	char *fmt = "%d";
	for (iter = vParts.rbegin(); iter != vParts.rend(); ++iter)
	{
		p += snprintf (p, e - p, fmt, *iter);
		fmt = ",%03d";
	}

	return dest;
}

static void	generate_report (const struct ginsu_cfg *cfg)
{
	std::set<ReportItem> vRpt;
	std::set<ReportItem>::const_iterator iter;
	char a[64], b[64];

	for (int i = 0; i < cfg->nSlices; i++)
	{
		const struct cfg_slice *slice = cfg->pSlices[i];
		if (slice->pkt_count)
		{
			ReportItem ri (slice);
			vRpt.insert (ri);
		}
	}

	printf ("%-23s %20s             %20s\n", " ", "Packets", "Bytes");

	format_size (a, sizeof(a), g_nTotalPackets);
	format_size (b, sizeof(b), g_nTotalBytes);
	printf ("Total Captured:         %20s             %20s\n", a, b);

	format_size (a, sizeof(a), g_nUnsorted);
	printf ("Unsorted:               %20s  (%5.2f %%)\n", a, perc(g_nUnsorted, g_nTotalPackets));

	for (iter = vRpt.begin(); iter != vRpt.end(); iter++)
	{
		const cfg_slice *s = iter->pSlice;	// For brevity.

		format_size (a, sizeof(a), s->pkt_count);
		format_size (b, sizeof(b), s->pkt_bytes);

		printf ("%-23s ", s->name);
		printf ("%20s  (%5.2f %%)  ", a, perc(s->pkt_count, g_nTotalPackets));
		printf ("%20s  (%5.2f %%)  ", b, perc(s->pkt_bytes, g_nTotalBytes));
		if (iter->pSlice->opts & OPT_NOSAVE)
		{
			printf ("NOSAVE");
		}
		printf ("\n");
	}
}

static inline struct cfg_slice* slice_packet (struct ginsu_cfg *cfg, const struct pcap_pkthdr *hdr, const u_char *data)
{
	for (int i = 0; i < cfg->nSlices; i++)
	{
		if (pcap_offline_filter (cfg->pSlices[i]->bpf, hdr, data))
		{
			return cfg->pSlices[i];
		}
	}

	return NULL;
}

static void process_packet (struct ginsu_cfg *cfg, const char *dev_name, pcap_t *pcap, const struct pcap_pkthdr *hdr, const u_char *data)
{
	struct cfg_slice	*slice = NULL;

	assert (cfg);
	assert (dev_name);
	assert (pcap);
	assert (hdr);
	assert (data);

	g_nTotalPackets++;
	g_nTotalBytes += hdr->len;

	if ((hdr->ts.tv_sec < g_nStart) || (hdr->ts.tv_sec > g_nStop))
	{
		g_nUnsorted++;
		return;
	}

	if (NULL == (slice = slice_packet (cfg, hdr, data)))
	{
		g_nUnsorted++;
		return;
	}

	slice->pkt_count++;
	slice->pkt_bytes += hdr->len;

	if (slice->opts & OPT_NOSAVE)
	{
		return;
	}

	if (!slice->buffer)
	{
		if (NULL == (slice->buffer = malloc (pcap_buff_size)))
		{
			fprintf (stderr, "malloc (%lu) failed.\n", pcap_buff_size);
			perror ("malloc");
			exit (EXIT_FAILURE);
		}
	}

	if (!slice->dumper)
	{
		char fname[PATH_MAX];
		char ts[64];
		struct tm *tm = localtime ((const time_t*)&(hdr->ts.tv_sec));

		strftime (ts, sizeof(ts), "%Y%m%d-%H%M%S", tm);

		snprintf (fname, sizeof(fname), "%s/%s.%06lu.%s.pcap", g_pszDestDir, ts, hdr->ts.tv_usec, slice->name);

//		printf ("Creating %s\n", fname);

		if (NULL == (slice->dumper = pcap_dump_open (pcap, fname)))
		{
			fprintf (stderr, "Failed to create '%s'\n%s\n", fname, pcap_geterr (pcap));
			exit (EXIT_FAILURE);
		}

		setbuffer (pcap_dump_file(slice->dumper), (char*)slice->buffer, pcap_buff_size);

		slice->est_file_size = pcap_dump_ftell (slice->dumper);
	}

	pcap_dump ((u_char*)slice->dumper, hdr, data);
	slice->est_file_size += sizeof (struct pcap_pkthdr) + hdr->caplen;


#if defined (_USE_FTELL)
	if (pcap_dump_ftell (slice->dumper) > MAX_DUMP_SIZE)
#else
	if (slice->est_file_size > MAX_DUMP_SIZE)
#endif
	{
		pcap_dump_close (slice->dumper);
		slice->dumper = NULL;
	}
}

static void	get_dev_name (char *dev_name, size_t maxlen, const char *filename)
{
	char	*dot = NULL;
	char	*base = NULL;
	char	path[PATH_MAX];

	assert (dev_name);
	assert (maxlen > 1);
	assert (filename);

	snprintf (path, sizeof(path), "%s", filename);

	if (NULL == (base = basename (path)))
	{
		snprintf (dev_name, maxlen, "unk0");
		return;
	}

	if (NULL == (dot = strchr (base, '.')))
	{
		snprintf (dev_name, maxlen, "unk0");
	}
	else
	{
		*dot = 0;
		snprintf (dev_name, maxlen, "%s", base);
	}
}

static void process_file (struct ginsu_cfg *cfg, const char *filename)
{
	char		errbuf [PCAP_ERRBUF_SIZE];
	char		dev_name[PATH_MAX];
	pcap_t		*pcap = NULL;
	struct pcap_pkthdr *hdr = NULL;
	const u_char	*data = NULL;
	int		r;
	void		*buffer = NULL;

// "ginsu-capture" names file as "ethXX.ts.ms.pcap" (dev.time.time_ms.pcap)
// Extract device name (first period delimited token from filename).
	get_dev_name (dev_name, sizeof(dev_name), filename);

	if (NULL == (pcap = pcap_open_offline (filename, errbuf)))
	{
		fprintf (stderr, "pcap_open_offline ('%s') failed.\n", filename);
		return;
	}

	if (NULL == (buffer = malloc (pcap_buff_size)))
	{
		fprintf (stderr, "malloc (%lu) failed.\n", pcap_buff_size);
		perror ("malloc");
		pcap_close (pcap);
		return;
	}

	setbuffer (pcap_file(pcap), (char*)buffer, pcap_buff_size);

	while (0 < (r = pcap_next_ex (pcap, &hdr, &data)))
	{
		process_packet (cfg, dev_name, pcap, hdr, data);
	}

	pcap_close (pcap);
	free (buffer);
}

static void queueDirectory (const char *dir, std::vector<InputFile> &vInputs)
{
	char		path[PATH_MAX];
	DIR		*pDir = NULL;
	struct dirent	*dirent = NULL;
	struct stat	statbuf;

	if (NULL == (pDir = opendir (dir)))
	{
		perror ("opendir");
		return;
	}

	while (NULL != (dirent = readdir (pDir)))
	{
		if (dirent->d_name[0] == '.') continue;

		if (dirent->d_type & DT_DIR)
		{
			snprintf (path, sizeof(path), "%s/%s", dir, dirent->d_name);
			queueDirectory (path, vInputs);
		}

		if (!(dirent->d_type & DT_REG)) continue;

		if (fnmatch ("*.pcap", dirent->d_name, FNM_PATHNAME)) continue;

		snprintf (path, sizeof(path), "%s/%s", dir, dirent->d_name);

		if (-1 == stat (path, &statbuf))
		{
			fprintf (stderr, "stat('%s') failed.\n", path);
			perror ("stat");
			exit (EXIT_FAILURE);
		}

		InputFile f;
		f.m_sFilename = path;
		f.m_nSize = statbuf.st_size;
		vInputs.push_back (f);
	}

	closedir(pDir);
}

static void usage (const char *prog)
{
	fprintf (stderr, "Usage: %s [opts]\n", prog);
	exit (-1);
}

int	main (int argc, char *argv[])
{
	int		i;
	char		*cfg_file = NULL;
	struct ginsu_cfg *cfg = NULL;
	std::vector<InputFile> vInputs;

	while (-1 != (i = getopt (argc, argv, "vhD:c:s:e:")))
	{
		switch (i)
		{
			case 'v':
				verbose++;
				break;

			case 'p':
				g_bProgressBar = false;
				break;

			case 'D':
				g_pszDestDir = optarg;
				break;

			case 'c':
				cfg_file = optarg;
				break;

			case 's':
				g_nStart = (time_t)atol(optarg);
				break;

			case 'e':
				g_nStop = (time_t)atol(optarg);
				break;

			case 'h':
			case '?':
				usage (argv[0]);
				break;
		}
	}

	if (cfg_file)
	{
		if (NULL == (cfg = ginsu_cfg_parse (cfg_file)))
		{
			fprintf (stderr, "Failed to parse '%s'.\n", cfg_file);
			exit (EXIT_FAILURE);
		}
	}

	if (!cfg)
	{
		fprintf (stderr, "Must specify a config file via '-c filename'.\n");
		usage (argv[0]);
	}

	if (!g_pszDestDir)
	{
		fprintf (stderr, "Must specify a destination directory via '-D dir'.\n");
		usage (argv[0]);

	}

	for (i = optind; i < argc; i++)
	{
		InputFile	f;
		struct stat	statbuf;
		char		temp[PATH_MAX];

		if (-1 == stat (argv[i], &statbuf))
		{
			fprintf (stderr, "stat('%s') failed.\n", argv[i]);
			perror ("stat");
			exit (EXIT_FAILURE);
		}

		if (S_ISDIR(statbuf.st_mode))
		{
			queueDirectory (argv[i], vInputs);
			continue;
		}

		if (!S_ISREG(statbuf.st_mode))
		{
			fprintf (stderr, "Not a file? '%s'\n", argv[i]);
			continue;
		}

		snprintf (temp, sizeof(temp), "%s", argv[i]);

		if (fnmatch ("*.pcap", basename(temp), FNM_PATHNAME))
		{
			fprintf (stderr, "Not a pcap file?  '%s'\n", argv[i]);
			continue;
		}

		f.m_sFilename = argv[i];
		f.m_nSize = statbuf.st_size;
		vInputs.push_back (f);
	}

	off64_t nTotalSize = 0;
	std::vector<InputFile>::iterator iter;
	for (iter = vInputs.begin(); iter != vInputs.end(); ++iter)
	{
		nTotalSize += iter->m_nSize;
	}

	char a[64], b[64];
	format_size (a, sizeof(a), nTotalSize);
	format_size (b, sizeof(b), vInputs.size());
	printf ("%s bytes in %s files.\n", a, b);

	off64_t nProcessed = 0;
	for (iter = vInputs.begin(); iter != vInputs.end(); ++iter)
	{
		process_file (cfg, iter->m_sFilename.c_str());

		nProcessed += iter->m_nSize;

		if (g_bProgressBar)
		{
			printf ("\rProgress: %6.3f%%\t", 100.0f * (double)nProcessed / (double)nTotalSize);
			fflush (stdout);
		}
	}

	if (g_bProgressBar)
	{
		printf ("\n\n");
	}

	if (g_nTotalPackets > 0)
	{
		generate_report (cfg);
	}

	if (cfg) ginsu_cfg_free (cfg);

	return 0;
}
