/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <assert.h>
#include <editline/readline.h>
#include <histedit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#define HISTORY_FILE ".kresc_history"
#define PROGRAM_NAME "kresc"

FILE *g_tty = NULL;		//!< connection to the daemon

static char *run_cmd(const char *cmd, uint32_t * msg_len);

char *prompt(EditLine * e)
{
	return PROGRAM_NAME "> ";
}

bool starts_with(const char *a, const char *b)
{
	if (strncmp(a, b, strlen(b)) == 0)
		return 1;
	return 0;
}

static unsigned char complete(EditLine * el, int ch)
{
	int argc, pos;
	const char **argv;
	const LineInfo *li = el_line(el);
	Tokenizer *tok = tok_init(NULL);
	// Parse the line.
	int ret = tok_line(tok, li, &argc, &argv, NULL, &pos);

	uint32_t msg_len;

	char *help = run_cmd("help()", &msg_len);
	if (!help) {
		perror("While communication with daemon");
		goto complete_exit;
	}

	if (ret != 0) {
		goto complete_exit;
	}

	if (argc == 0) {
		printf("\n%s", help);
	}

	char *lines;
	lines = strtok(help, "\n");
	int matches = 0;
	bool exactmatch = 0;
	char *lastmatch;
	int i = 0;
	while (lines != NULL) {
		if (!(i % 2))
			if (argv[0] && starts_with(lines, argv[0])) {
				printf("\n%s", lines);
				lastmatch = lines;
				matches++;
				if (!strcmp(lines, argv[0]))
					exactmatch = 1;
			}
		lines = strtok(NULL, "\n");
		i++;
	}
	printf("\n");
	if (matches == 1) {
		char *brace = strchr(lastmatch, '(');
		if (brace != NULL)
			*(brace + 1) = '\0';
		el_deletestr(el, pos);
		el_insertstr(el, lastmatch);
		pos = strlen(lastmatch);
		if (exactmatch && brace == NULL) {
			char *prettyprint = run_cmd(lastmatch, &msg_len);
			printf("%s", prettyprint);
			el_insertstr(el, ".");
			free(prettyprint);
		}
	}

complete_exit:
	free(help);
	tok_reset(tok);
	tok_end(tok);
	return CC_REDISPLAY;
}

//! Initialize connection to the daemon; return 0 on success.
static int init_tty(const char *path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return 1;

	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	size_t plen = strlen(path);
	if (plen + 1 > sizeof(addr.sun_path)) {
		fprintf(stderr, "Path too long\n");
		return 1;
	}
	memcpy(addr.sun_path, path, plen + 1);
	if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr))) {
		perror("While connecting to daemon");
		return 1;
	}

	g_tty = fdopen(fd, "r+");
	if (!g_tty) {
		perror("While opening TTY");

		return 1;
	}
	// Switch to binary mode and consume the text "> ".
	if (fprintf(g_tty, "__binary\n") < 0 || !fread(&addr, 2, 1, g_tty)
	    || fflush(g_tty)) {
		perror("While initializing TTY");
		return 1;
	}

	return 0;
}

//! Run a command on the daemon; return the answer or NULL on failure.
static char *run_cmd(const char *cmd, uint32_t * msg_len)
{
	if (!g_tty || !cmd) {
		assert(false);
		return NULL;
	}
	printf("cmd: %s\n", cmd);

	if (fprintf(g_tty, "%s", cmd) < 0 || fflush(g_tty))
		return NULL;
	uint32_t len;
	if (!fread(&len, sizeof(len), 1, g_tty))
		return NULL;
	char *msg = malloc(1 + (size_t) len);
	if (!msg)
		return NULL;
	if (len && !fread(msg, len, 1, g_tty)) {
		free(msg);
		return NULL;
	}
	msg[len] = '\0';
	*msg_len = len;
	return msg;
}

static int interact()
{

	EditLine *el;
	History *hist;
	int count;
	const char *line;
	int keepreading = 1;
	HistEvent ev;
	el = el_init(PROGRAM_NAME, stdin, stdout, stderr);
	el_set(el, EL_PROMPT, &prompt);
	el_set(el, EL_EDITOR, "emacs");
	el_set(el, EL_ADDFN, PROGRAM_NAME "-complete",
	       "Perform " PROGRAM_NAME " completion.", complete);
	el_set(el, EL_BIND, "^I", PROGRAM_NAME "-complete", NULL);

	hist = history_init();
	if (hist == 0) {
		perror("While initializing command history");
		return 1;
	}
	history(hist, &ev, H_SETSIZE, 800);
	el_set(el, EL_HIST, history, hist);

	const char hist_file[] = HISTORY_FILE;
	history(hist, &ev, H_LOAD, hist_file);

	while (keepreading) {
		line = el_gets(el, &count);
		if (count > 0) {
			history(hist, &ev, H_ENTER, line);
			uint32_t msg_len;
			char *msg = run_cmd(line, &msg_len);
			if (!msg) {
				perror("While communication with daemon");
				history_end(hist);
				el_end(el);
				free(msg);
				return 1;
			}
			printf("%s", msg);
			if (msg_len == 0 || msg[msg_len - 1] != '\n') {
				printf("\n");
			}
			printf("%d\n", msg_len);
			history(hist, &ev, H_SAVE, hist_file);

			free(msg);
		}
	}
	history_end(hist);
	el_end(el);
	if (feof(stdin))
		return 0;
	perror("While reading input");
	return 1;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s tty/xxxxx\n", argv[0]);
		return 1;
	}

	int res = init_tty(argv[1]);

	if (!res)
		res = interact();

	if (g_tty)
		fclose(g_tty);
	return res;
}
