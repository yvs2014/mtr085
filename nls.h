#ifndef NLS_H
#define NLS_H

#ifdef USE_NLS
#include <libintl.h>
#define _(text) gettext(text)
#else
#define _(text) (text)
#endif

// TUI
#define OPTS_STR       _("Keys")
#define _HINTS_STR     _("ints") // [h]ints
#define _QUIT_STR      _("uit")  // [q]uit
#define FIELDS_STR     _("Fields")
#define USR_FIELDS_STR _("Custom fields")
#define PACKETS_STR    _("Packets")
#define PINGS_STR      _("Pings")
#define CYCLE0NO_STR   _("0 for unlimit")
#define TOS_HINT_STR   _("ToS bits: lowcost(1), reliability(2), throughput(4), lowdelay(8)")
#define PSIZE_CHNG_STR _("Change payload size")
#define NEG4RND_STR    _("negative values are for random")
#define RANGE_STR      _("range")
#define RANGENEG_STR   _("range[0-255], random is -1")
#define GAPINSEC_STR   _("Interval in seconds")
#define LESSTHAN_STR   _("less than")
#define MORETHAN_STR   _("more than")
#define UNKNOWN_STR    _("Unknown")
#define HISTOGRAM_STR  _("Histogram")
#define HCOLS_STR      _("columns")
#define SCALE_STR      _("Scale")
#define MSEC_STR       _("ms")
//
#define PAR_UDP_STR    _("udp")
#define PAR_TCP_STR    _("tcp")
#define PAR_MPLS_STR   _("mpls")
#define PAR_ASN_STR    _("asn")
#define PAR_DNS_STR    _("dns")
#define PAR_JITTER_STR _("jitter")
#define PAR_CHART_STR  _("chart")
#define PAR_PATT_STR   _("pattern")
#define PAR_DT_STR     _("dt")
#define PAR_CYCLES_STR _("cycles")
#define PAR_TTL_STR    _("ttl")
#define PAR_QOS_STR    _("qos")
#define PAR_SIZE_STR   _("size")
#define PAR_CACHE_STR  _("cache")
#define PAR_PAUSED_STR _("on pause")


// hop info with init fields
#define HOST_STR      _("Host")
#define _II_ASN_STR    "ASN"
#define _II_ROUTE_STR  "Route"
#define _II_CC_STR     "CC"
#define _II_REG_STR    "Registry"
#define _II_ALLOC_STR  "Allocated"
#define _II_ORIGIN_STR "Origin"
#define _II_DESC_STR   "Descr"
#define _II_ASPATH_STR "AS Path"
#define _II_ORG_STR    "Org"
#define _II_CNAME_STR  "Country"
#define _II_RC_STR     "RC"
#define _II_RNAME_STR  "Region"
#define _II_CITY_STR   "City"
#define _II_ZIP_STR    "Zip"
#define _II_LAT_STR    "Lat"
#define _II_LNG_STR    "Long"
#define _II_TZ_STR     "TZ"
#define _II_ISP_STR    "ISP"
#define _II_ASNAME_STR "AS Name"

// stat init fields
#define _GAP_HINT   "Space between fields"
#define _LOSS_STR   "Loss"
#define _LOSS_HINT  "Loss Ratio"
#define _DROP_STR   "Drop"
#define _DROP_HINT  "Dropped Packets"
#define _RECV_STR   "Recv"
#define _RECV_HINT  "Received Packets"
#define _SENT_STR   "Sent"
#define _SENT_HINT  "Sent Packets"
#define _LAST_STR   "Last"
#define _LAST_HINT  "Newest RTT(ms)"
#define _BEST_STR   "Best"
#define _BEST_HINT  "Min/Best RTT(ms)"
#define _AVRG_STR   "Avrg"
#define _AVRG_HINT  "Average RTT(ms)"
#define _WRST_STR   "Wrst"
#define _WRST_HINT  "Max/Worst RTT(ms)"
#define _STDEV_STR  "StDev"
#define _STDEV_HINT "Standard Deviation"
#define _GAVR_STR   "GAvr"
#define _GAVR_HINT  "Geometric Mean"
#define _JTTR_STR   "Jttr"
#define _JTTR_HINT  "Current Jitter"
#define _JAVG_STR   "Javg"
#define _JAVG_HINT  "Jitter Mean/Avrg"
#define _JMAX_STR   "Jmax"
#define _JMAX_HINT  "Worst Jitter"
#define _JINT_STR   "Jint"
#define _JINT_HINT  "Interarrival Jitter"

// cmd help
#define COMMANDS_STR _("Commands")
#define CMD_B_STR    _("set bit pattern in range 0..255 (negative value means random)")
#define CMD_C_STR    _("set number of cycles to run (no limit: 0)")
#define CMD_D_STR    _("switch display mode")
#define CMD_E_STR    _("toggle MPLS info")
#define CMD_F_STR    _("set first TTL (default 1)")
#define CMD_I_STR    _("set interval in seconds (default 1s)")
#define CMD_J_STR    _("toggle latency/jitter stats (default: latency)")
#define CMD_L_STR    _("toggle ASN lookup")
#define CMD_LL_STR   _("switch IP info")
#define CMD_M_STR    _("set max TTL (default 30)")
#define CMD_N_STR    _("toggle DNS")
#define CMD_O_STR    _("set stat fields to display (default: LS_NABWV)")
#define CMD_Q_STR    _("quit")
#define CMD_QQ_STR   _("set ToS/QoS (quality of service)")
#define CMD_R_STR    _("reset statistics")
#define CMD_S_STR    _("set payload size (default 56), randomly within size range if it's negative")
#define CMD_T_STR    _("toggle TCP pings")
#define CMD_U_STR    _("toggle UDP pings")
#define CMD_X_STR    _("toggle cache mode")
#define CMD_PM_STR   _("scroll up/down")
#define CMD_SP_STR   _("pause/resume")
#define SPACE_STR    _("SPACE")
#define CH_NUM_STR   _("<number>")
#define CH_STR_STR   _("<string>")

// cli help
#define CLI_USAGE_STR _("Usage")
#define CLI_TGT_STR   _("TARGET[:PORT]")
#define CLI_ADDR_STR  _("IP.ADD.RE.SS")
#define CLI_NUM_STR   _("NUMBER")
#define CLI_CNT_STR   _("COUNT")
#define CLI_MODE_STR  _("MODE")
#define CLI_FLD_STR   _("FIELDS")
#define CLI_SEC_STR   _("SECONDS")
#define CLI_IINFO_STR _("SERVER,FIELDS")
#define CLI_BYTE_STR  _("BYTES")

// option hints
#define BITPATT_STR    _("Bit pattern")
#define CYCLESNO_STR   _("Number of cycles")
#define MINTTL_STR     _("First TTL")
#define MAXTTL_STR     _("Max TTL")
#define INTERVAL_STR   _("Interval")
#define QOSTOS_STR     _("QoS/ToS")
#define PSIZE_STR      _("Payload size")
#define MUTEXCL_ERR    _("Mutually exclusive options")
#define TCP_TOUT_STR   _("TCP timeout")
#define CACHE_TOUT_STR _("Cache timeout")

// misc
#define TARGET_STR     _("target")
#define TARGETS_STR    _("targets")
#define TARGET_CAPSTR  _("Target")
#define SOURCE_STR     _("source")
#define ARGS_STR       _("args")
#define PORTNUM_STR    _("port number")
#define MAX_STR        _("max")
#define OPENED_STR     _("opened")
#define CLOSED_STR     _("closed")
#define QUERIES_STR    _("queries")
#define REPLIES_STR    _("replies")
#define NONE_STR       _("NONE")
#define DATETIME_STR   _("datetime")
#define HOP_STR        _("hop")
#define DATA_STR       _("data")
#define ACTIVE_STR     _("active")
#define IPINFO_STR     _("ipinfo")
#define YES_STR        _("yes")
#define NO_STR         _("no")
#define ERROR_STR      _("error")
#define CSV_HOP_STR    _("Hop")
#define CSV_STATUS_STR _("Status")
#define CSV_INFO_STR   _("Info")

// messages
#define ANYCONT_STR  _("Press any key to continue")
#define ANYQUIT_STR  _("Press any key to quit")
#define UNKNOWN_ERR  _("Unknown error")
#define RAWSOCK_ERR  _("Unable to get raw sockets")
#define DROPPERM_ERR _("Unable to drop permissions")
#define DROPCAP_ERR  _("Unable to drop capabilities")
#define RESFAIL_ERR  _("Failed to resolve")
#define MANYNS_WARN  _("Only one DNS server is used")
#define PARSE_ERR    _("Failed to parse")
#define SETNS_ERR    _("Failed to set nameserver")
#define OPENDISP_ERR _("Unable to open display")
#define TCLASS6_ERR  _("IPv6 traffic class is not supported")
#define DISPMODE_ERR _("Display mode")
#define OVERFLD_ERR  _("Too many stat fields")
#define UNKNFLD_ERR  _("Unknown stat field")
#define HOSTENT_ERR  _("Unable to set host entry")
#define USEADDR_ERR  _("Unable to use address")
#define UNOPRINT_ERR _("UTF8 is not printable")
#define NOADDR_ERR   _("No address found")
//
#define NOPOOLMEM_ERR _("No place in pool for sockets")
#define NOSOCK6_ERR   _("No IPv6 sockets")
#define NODNS_ERR     _("No nameservers")


#endif
