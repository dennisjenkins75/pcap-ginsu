/*	ginsu/config.c

	Parses config file for 'ginsu'.
*/

#include "ginsu.h"

// Input: bpf expression of form "xxx"
// Output: bpf expression of form "(xxx) or (yyy)", where yyy = xxx with src/dst replaced with dst/src.
static char*	bpf_mirror (const char *bpf_src)
{
	char	*mirror = strdup(bpf_src);
	char	*result = (char*)malloc(strlen(bpf_src) * 2 + 32); 	// "+9 should be enough..?"
	char	*a, *p, *q;

	a = mirror;
	p = strstr(a, "dst");
	q = strstr(a, "src");

	while (p || q)
	{
		if ((q && !p) || (q && (q < p)))
		{
			memcpy (q, "dst", 3);
			q = strstr (q + 3, "src");
			continue;
		}

		if ((p && !q) || (p && (p < q)))
		{
			memcpy (p, "src", 3);
			p = strstr (p + 3, "dst");
			continue;
		}

		fprintf (stderr, "crap. mirror, q, p, q = %p, %p, %p, %p\n", mirror, q, p, q);
		exit (-1);
	}

	if (strcmp (bpf_src, mirror))	// did we make any changes?
	{
		sprintf (result, "(%s) or (%s)", bpf_src, mirror);
		return result;
	}

	free (result);
	return strdup(bpf_src);
}

static int	add_slice (pcap_t *pcap, struct ginsu_cfg *cfg, const char *name, const char *bpf_src, int opts)
{
	struct cfg_slice	*slice = NULL;
	struct bpf_program	*bpf = NULL;
	char			*alt_src = NULL;
	int			optimize = 1;
	bpf_u_int32		netmask = 0;

	bpf = (struct bpf_program*) malloc (sizeof (struct bpf_program));

	if (!(opts & OPT_NOMIRROR))
	{
		alt_src = bpf_mirror (bpf_src);
	}

	if (-1 == pcap_compile (pcap, bpf, alt_src ? alt_src : bpf_src, optimize, netmask))
	{
		fprintf (stderr, "BPF syntax error in filter for '%s':\n%s\n", name, pcap_geterr (pcap));
		free (bpf);
		if (alt_src) free (alt_src);
		return 0;
	}

	slice = (struct cfg_slice*)malloc (sizeof(struct cfg_slice));
	memset (slice, 0, sizeof (struct cfg_slice));
	slice->name = strdup (name);
	slice->bpf_src = strdup (bpf_src);
	slice->opts = opts;
	slice->bpf = bpf;
	slice->pkt_count = 0;
	slice->pkt_bytes = 0;
	slice->dumper = 0;
	slice->buffer = NULL;
	slice->est_file_size = 0;

	if (cfg->nSlices >= cfg->nMaxSlices)
	{
		cfg->nMaxSlices += 16;
		cfg->pSlices = (struct cfg_slice**)realloc (cfg->pSlices, cfg->nMaxSlices * sizeof (struct cfg_slice*));
	}

	cfg->pSlices[cfg->nSlices++] = slice;

	if (alt_src) free (alt_src);

	return 1;
}

// Define config file grammar via "libconfuse" structs.
static cfg_opt_t slice_opts[] =
{
	CFG_STR ("bpf", "", CFGF_NONE),
	CFG_STR_LIST ("options", "", CFGF_NONE),
	CFG_END ()
};

static cfg_opt_t alias_opts[] =
{
	CFG_STR_LIST ("list", "", CFGF_NONE),
	CFG_END ()
};

static cfg_opt_t opts[] =
{
	CFG_SEC ("alias", alias_opts, CFGF_TITLE | CFGF_MULTI),
	CFG_SEC ("slice", slice_opts, CFGF_TITLE | CFGF_MULTI | CFGF_NO_TITLE_DUPES),
	CFG_END ()
};

struct ginsu_cfg*	ginsu_cfg_parse (const char *cfg_filename)
{
	struct ginsu_cfg	*ginsu = NULL;
	pcap_t			*pcap = NULL;
	cfg_t			*conf = NULL;		// libconfuse
	int			ok = 1;
	int			cnt_alias = 0;
	int			cnt_slice = 0;

	pcap = pcap_open_dead (DLT_EN10MB, 65535);

	if (NULL == (conf = cfg_init (opts, CFGF_NONE)))
	{
		fprintf (stderr, "cfg_init() failed unexpectedly.\n");
		pcap_close (pcap);
		return NULL;
	}

	ok = cfg_parse (conf, cfg_filename);

	if (CFG_PARSE_ERROR == ok)
	{
		fprintf (stderr, "failed to parse '%s'.\n", cfg_filename);
		pcap_close (pcap);
		return NULL;
	}
	else if (CFG_FILE_ERROR == ok)
	{
		fprintf (stderr, "file error parsing '%s'.\n", cfg_filename);
		perror (cfg_filename);
		pcap_close (pcap);
		return NULL;
	}

// How many aliases and slices do we have?
	cnt_slice = cfg_size (conf, "slice");
	cnt_alias = cfg_size (conf, "alias");

	if (!cnt_slice)
	{
		fprintf (stderr, "Error, no slices defined in config file '%s'\n", cfg_filename);
		pcap_close (pcap);
		return NULL;
	}

	ginsu = (struct ginsu_cfg*) malloc (sizeof (struct ginsu_cfg));
	ginsu->cfg_file = strdup (cfg_filename);
	ginsu->ts = time(NULL);
	ginsu->nSlices = 0;
	ginsu->nMaxSlices = cnt_slice;
	ginsu->pSlices = (struct cfg_slice**)malloc (ginsu->nMaxSlices * sizeof (struct cfg_slice*));

// Process host aliases first.
/*
	for (int i = 0; i < cnt_alias; i++)
	{
		cfg_t *iter = cfg_getnsec (conf, "alias", i);
		const char *alias = cfg_title (iter);
		int list_count = cfg_size (iter, "list");

		for (int j = 0; j < list_count; j++)
		{
			const char *val = cfg_getnstr (iter, "list", j);
			printf ("%s = %s\n", alias, val);
		}
	}
*/

// Process slices.
	ok = 1;
	for (int i = 0; i < cnt_slice; i++)
	{
		cfg_t *iter = cfg_getnsec (conf, "slice", i);
		const char *title = cfg_title (iter);
		const char *bpf_src = cfg_getstr (iter, "bpf");
		int cnt_options = cfg_size (iter, "options");
		int slice_opts = 0;

		for (int j = 0; j < cnt_options; j++)
		{
			const char *opt_name = cfg_getnstr (iter, "options", j);

			if (!strcmp(opt_name, "nomirror")) { slice_opts |= OPT_NOMIRROR; }
			else if (!strcmp(opt_name, "nosave")) {slice_opts |= OPT_NOSAVE; }
			else { fprintf (stderr, "Unknown option '%s' in slice '%s'.\n", opt_name, title); }
		}

		ok &= add_slice (pcap, ginsu, title, bpf_src, slice_opts);
	}

	pcap_close (pcap);

	cfg_free (conf);

	if (!ok)
	{
		ginsu_cfg_free (ginsu);
		ginsu = NULL;
	}

	return ginsu;
}

void	ginsu_cfg_free (struct ginsu_cfg *ginsu)
{
	if (!ginsu) return;

	free (ginsu->cfg_file);

	for (int i = 0; i < ginsu->nSlices; i++)
	{
		struct cfg_slice *slice = ginsu->pSlices[i];

		if (slice->dumper) pcap_dump_close (slice->dumper);
		if (slice->buffer) free (slice->buffer);

		free (slice->name);
		free (slice->bpf_src);
		pcap_freecode (slice->bpf);
		free (slice);
	}

	free (ginsu->pSlices);
	free (ginsu);
}
