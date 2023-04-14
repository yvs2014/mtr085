#ifndef GRAPHCAIRO_H
#define GRAPHCAIRO_H

// two sets to not detect ##/VA_OPT
#ifdef GCDEBUG
#define GCMSG(lit)       printf(lit)
#define GCMSG_(fmt, ...) printf(fmt, __VA_ARGS__)
#else
#define GCMSG(lit)       {}
#define GCMSG_(fmt, ...) {}
#endif

#define POS_ROUND(x) ((int)((x) + 0.5))
#define ACTION_RESIZE -1

typedef struct {
  int graph_type;
  int period;
  bool enable_legend;
  bool enable_multipath;
  bool jitter_graph;
  int cols_max;
  int path_max;
  int label_max;
} cr_params_t;

bool cr_open(cr_params_t *cr_params);
void cr_close(void);
int cr_dispatch_event(void);
void cr_redraw(int *data);
void cr_set_hops(int curr_hops, int min_hop);
void cr_net_reset(int paused);

int cr_recalc(int hostinfo_max);
void cr_init_legend(void);
void cr_print_legend_header(char *header);
void cr_print_legend_footer(char *footer);
void cr_print_hop(int at);
void cr_print_host(int at, int data, char *host, char *stat);
int cr_display_offset(void);

#endif
