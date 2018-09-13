#include "contrib/backtrace.h"

#include <stdlib.h>
#include <stdio.h>

#ifdef ENABLE_BACKTRACE
#define UNW_LOCAL_ONLY
#include <libunwind.h>

const char *identical_sp_error = "unwinding error: previous frame identical to this frame (corrupt stack?)";
static char backtrace_buf[4096 * 4];

const char *backtrace()
{
	int frame_no = 0;
	unw_word_t sp = 0, old_sp = 0, ip, offset;
	unw_context_t unw_context;
	unw_getcontext(&unw_context);
	unw_cursor_t unw_cur;
	unw_init_local(&unw_cur, &unw_context);
	char *p = backtrace_buf;
	char *end = p + sizeof(backtrace_buf) - 1;

	while (unw_step(&unw_cur) > 0) {
		old_sp = sp;
		unw_get_reg(&unw_cur, UNW_REG_IP, &ip);
		unw_get_reg(&unw_cur, UNW_REG_SP, &sp);
		if (sp == old_sp) {
			break;
		}
		char sym[4096];
		unw_get_proc_name(&unw_cur, sym, sizeof(sym), &offset);
		p += snprintf(p, end - p, "#%-2d %p in ", frame_no, (void *)ip);
		if (p >= end) {
			break;
		}
		p += snprintf(p, end - p, "%s+%lx", sym, (long)offset);
		if (p >= end) {
			break;
		}
		p += snprintf(p, end - p, "\n");
		if (p >= end) {
			break;
		}
		++frame_no;
	}

	*p = '\0';
	return backtrace_buf;
}

#else

const char *backtrace()
{
	return "\n";
}

#endif
