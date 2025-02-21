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

// hop info
#define HOST_STR _("Host")

// stats
#define GAP_HINT   _("Space between fields")
#define LOSS_STR   _("Loss")
#define LOSS_HINT  _("Loss Ratio")
#define DROP_STR   _("Drop")
#define DROP_HINT  _("Dropped Packets")
#define RECV_STR   _("Recv")
#define RECV_HINT  _("Received Packets")
#define SENT_STR   _("Sent")
#define SENT_HINT  _("Sent Packets")
#define LAST_STR   _("Last")
#define LAST_HINT  _("Newest RTT(ms)")
#define BEST_STR   _("Best")
#define BEST_HINT  _("Min/Best RTT(ms)")
#define AVRG_STR   _("Avrg")
#define AVRG_HINT  _("Average RTT(ms)")
#define WRST_STR   _("Wrst")
#define WRST_HINT  _("Max/Worst RTT(ms)")
#define STDEV_STR  _("StDev")
#define STDEV_HINT _("Standard Deviation")
#define MEAN_STR   _("Mean")
#define MEAN_HINT  _("Geometric Mean")
#define JTTR_STR   _("Jttr")
#define JTTR_HINT  _("Current Jitter")
#define JAVG_STR   _("Javg")
#define JAVG_HINT  _("Jitter Mean/Avrg")
#define JMAX_STR   _("Jmax")
#define JMAX_HINT  _("Worst Jitter")
#define JINT_STR   _("Jint")
#define JINT_HINT  _("Interarrival Jitter")

// messages
#define ANYCONT_STR  _("Press any key to continue")
#define ANYQUIT_STR  _("Press any key to quit")

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
#define CH_INT_STR   _("<int>")
#define CH_STR_STR   _("<string>")

// cli help
#define CLI_USAGE_STR _("Usage")
#define CLI_TGT_STR   _("TARGET")
#define CLI_PORT_STR  _("PORT")
#define CLI_ADDR_STR  _("IP.ADD.RE.SS")
#define CLI_NUM_STR   _("NUMBER")
#define CLI_CNT_STR   _("COUNT")
#define CLI_MODE_STR  _("MODE")
#define CLI_FLD_STR   _("FIELDS")
#define CLI_SEC_STR   _("SECONDS")
#define CLI_IINFO_STR _("SERVER,FIELDS")
#define CLI_BYTE_STR  _("BYTES")

#endif
