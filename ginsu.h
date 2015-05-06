/*	ginsu/ginsu.h

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pcapnav.h>
//#include <limits.h>
//#include <pwd.h>
//#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
//#include <fcntl.h>
#include <unistd.h>
//#include <signal.h>
#include <assert.h>
#include <time.h>
#include <dirent.h>
#include <fnmatch.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Gentoo package "dev-libs/confuse-2.6-r3"
#include <confuse.h>

#include <vector>
#include <set>
#include <string>


// Get struct defs for ethernet, ip, tcp and udp headers
#include "ethernet.h"

#define MAX_DEV_NAME_LEN 32

#define OPT_NOSAVE 1
#define OPT_NOMIRROR 2


class	InputFile
{
public:
	std::string	m_sFilename;
	off64_t		m_nSize;
};



// Holds data obtained from a parsed config file.
struct cfg_slice
{
// Raw config from config file.
	char	*name;
	char	*bpf_src;
	int	opts;

// Internal info attached to this "slice"
	struct bpf_program *bpf;
	off64_t pkt_count;
	off64_t pkt_bytes;	// Total bytes in link-layer.

// This info is specific to the output file.
	pcap_dumper_t	*dumper;
	void 		*buffer;
	size_t		est_file_size;
};

struct	ginsu_cfg
{
	char	*cfg_file;
	time_t	ts;
	int	nSlices;
	int	nMaxSlices;
	struct cfg_slice **pSlices;
};

struct ginsu_cfg*	ginsu_cfg_parse (const char *cfg_filename);
void			ginsu_cfg_free (struct ginsu_cfg *cfg);
