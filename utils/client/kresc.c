/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <arpa/inet.h>
#include <assert.h>
#include <contrib/ccan/asprintf/asprintf.h>
#include <editline/readline.h>
#include <errno.h>
#include <histedit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define HISTORY_FILE "kresc_history"
#define PROGRAM_NAME "kresc"

FILE *g_tty = NULL;		//!< connection to the daemon

static char *run_cmd(const char *cmd, size_t * out_len);

const char *prompt(EditLine * e)
{
	return PROGRAM_NAME "> ";
}

bool starts_with(const char *a, const char *b)
{
	if (strncmp(a, b, strlen(b)) == 0)
		return 1;
	return 0;
}

//! Returns Lua name of type of value, NULL on error. Puts length of type in name_len;
const char *get_type_name(const char *value)
{
	if (value == NULL) {
		return NULL;
	}

	for (int i = 0; value[i]; i++) {
		if (value[i] == ')') {
			//Return NULL to prevent unexpected function call
			return NULL;
		}
	}

	char *cmd = afmt("type(%s)", value);

	if (!cmd) {
		perror("While tab-completing.");
		return NULL;
	}

	size_t name_len;
	char *type = run_cmd(cmd, &name_len);
	if (!type) {
		return NULL;
	} else {
		free(cmd);
	}

	if (starts_with(type, "[")) {
		//Return "nil" on non-valid name.
		free(type);
		return "nil";
	} else {
		type[(strlen(type)) - 1] = '\0';
		return type;
	}
}

static void complete_function(EditLine * el)
{
	//Add left parenthesis to function name.
	el_insertstr(el, "(");
}

static void complete_members(EditLine * el, const char *str,
			     const char *str_type, int str_len, char *dot)
{
	char *table = strdup(str);
	if (!table) {
		perror("While tab-completing");
		return;
	}
	//Get only the table name (without partial member name).
	if (dot) {
		*(table + (dot - str)) = '\0';
	}
	//Insert a dot after the table name.
	if (!strncmp(str_type, "table", 5)) {
		el_insertstr(el, ".");
		str_len++;
	}
	//Check if the substring before dot is a valid table name.
	const char *t_type = get_type_name(table);
	if (t_type && !strncmp("table", t_type, 5)) {
		//Get string of members of the table.
		char *cmd =
		    afmt
		    ("do local s=\"\"; for i in pairs(%s) do s=s..i..\"\\n\" end return(s) end",
		     table);
		if (!cmd) {
			perror("While tab-completing.");
			goto complete_members_exit;
		}
		size_t members_len;
		char *members = run_cmd(cmd, &members_len);
		free(cmd);
		if (!members) {
			perror("While communication with daemon");
			goto complete_members_exit;
		}
		//Split members by newline.
		char *members_tok = strdup(members);
		free(members);
		if (!members_tok) {
			goto complete_members_exit;
		}
		char *token = strtok(members_tok, "\n");
		int matches = 0;
		char *lastmatch = NULL;
		if (!dot || dot - str + 1 == strlen(str)) {
			//Prints all members.
			while (token) {
				char *member = afmt("%s.%s", table, token);
				const char *member_type = get_type_name(member);
				if (member && member_type) {
					printf("\n%s (%s)", member, member_type);
					free(member);
					free((void *)member_type);
				} else if (member) {
					printf("\n%s", member);
					free(member);
				}
				token = strtok(NULL, "\n");
				matches++;
			}
		} else {
			//Print members matching the current line.
			while (token) {
				if (str && starts_with(token, dot + 1)) {
					const char *member_type =
					    get_type_name(afmt
							  ("%s.%s", table,
							   token));
					if (member_type) {
						printf("\n%s.%s (%s)", table,
						       token, member_type);
						free((void *)member_type);
					} else {
						printf("\n%s.%s", table, token);
					}
					lastmatch = token;
					matches++;
				}
				token = strtok(NULL, "\n");
			}

			//Complete matching member.
			if (matches == 1) {
				el_deletestr(el, str_len);
				el_insertstr(el, table);
				el_insertstr(el, ".");
				el_insertstr(el, lastmatch);
			}
		}
		if (matches > 1) {
			printf("\n");
		}
		free(members_tok);
	}

complete_members_exit:
	free(table);
	if(t_type) {
		free((void*)t_type);
	}
}

static void complete_globals(EditLine * el, const char *str, int str_len)
{
	//Parse Lua globals.
	size_t globals_len;
	char *globals = run_cmd("_G.__orig_name_list", &globals_len);
	if (!globals) {
		perror("While tab-completing");
		return;
	}
	//Show possible globals.
	char *globals_tok = strdup(globals);
	free(globals);
	if (!globals_tok) {
		return;
	}
	char *token = strtok(globals_tok, "\n");
	int matches = 0;
	char *lastmatch = NULL;
	while (token) {
		if (str && starts_with(token, str)) {
			printf("\n%s (%s)", token, get_type_name(token));
			lastmatch = token;
			matches++;
		}
		token = strtok(NULL, "\n");
	}
	if (matches > 1) {
		printf("\n");
	}
	//Complete matching global.
	if (matches == 1) {
		el_deletestr(el, str_len);
		el_insertstr(el, lastmatch);
	}
	free(globals_tok);
}

static unsigned char complete(EditLine * el, int ch)
{
	int argc, pos;
	const char **argv;
	const LineInfo *li = el_line(el);
	Tokenizer *tok = tok_init(NULL);

	//Tokenize current line.
	int ret = tok_line(tok, li, &argc, &argv, NULL, &pos);

	if (ret != 0) {
		perror("While tab-completing.");
		goto complete_exit;
	}
	//Show help.
	if (argc == 0) {
		size_t help_len;
		char *help = run_cmd("help()", &help_len);
		if (help) {
			printf("\n%s", help);
			free(help);
		} else {
			perror("While communication with daemon");
		}
		goto complete_exit;
	}

	if (argc > 1) {
		goto complete_exit;
	}
	//Get name of type of current line.
	const char *type = get_type_name(argv[0]);

	if (!type) {
		goto complete_exit;
	}
	//Get position of last dot in current line (useful for parsing table).
	char *dot = strrchr(argv[0], '.');

	if (strncmp(type, "table", 5) != 0 && !dot) {
		//Line is not a name of some table and there is no dot in it.
		complete_globals(el, argv[0], pos);
	} else if ((dot && strncmp(type, "nil", 3) == 0)
		   || strncmp(type, "table", 5) == 0) {
		//Current line (or part of it) is a name of some table.
		complete_members(el, argv[0], type, pos, dot);
	} else if (strncmp(type, "function", 8) == 0) {
		//Current line is a function.
		complete_function(el);
	}
	if (type) {
		free((void *)type);
	}

complete_exit:
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
		close(fd);
		return 1;
	}
	memcpy(addr.sun_path, path, plen + 1);
	if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr))) {
		perror("While connecting to daemon");
		close(fd);
		return 1;
	}
	g_tty = fdopen(fd, "r+");
	if (!g_tty) {
		perror("While opening TTY");
		close(fd);
		return 1;
	}

	// Switch to binary mode and consume the text "> ".
	if (fprintf(g_tty, "__binary\n") < 0 || !fread(&addr, 2, 1, g_tty)
	    || fflush(g_tty)) {
		perror("While initializing TTY");
		fclose(g_tty);
		g_tty = NULL;
		return 1;
	}

	return 0;
}

//! Run a command on the daemon; return the answer or NULL on failure, puts answer length to out_len.
static char *run_cmd(const char *cmd, size_t * out_len)
{
	if (!g_tty || !cmd) {
		assert(false);
		return NULL;
	}
	if (fprintf(g_tty, "%s", cmd) < 0 || fflush(g_tty))
		return NULL;
	uint32_t len;
	if (!fread(&len, sizeof(len), 1, g_tty))
		return NULL;
	len = ntohl(len);
	char *msg = malloc(1 + (size_t) len);
	if (!msg)
		return NULL;
	if (len && !fread(msg, len, 1, g_tty)) {
		free(msg);
		return NULL;
	}
	msg[len] = '\0';
	*out_len = len;
	return msg;
}

static int interact()
{
	EditLine *el;
	History *hist;
	int count;
	const char *line;
	HistEvent ev;
	el = el_init(PROGRAM_NAME, stdin, stdout, stderr);
	el_set(el, EL_PROMPT, prompt);
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

	char *hist_file = NULL;

	char *data_home = getenv("XDG_DATA_HOME");

	//Check whether $XDG_DATA_HOME is set.
	if (!data_home || *data_home == '\0') {
		const char *home = getenv("HOME");	//This should be set on any POSIX compliant OS, even for nobody

		//Create necessary folders.
		char *dirs[3] =
		    { afmt("%s/.local", home), afmt("%s/.local/share", home),
			afmt("%s/.local/share/knot-resolver/", home)
		};
		bool ok = true;
		for (int i = 0; i < 3; i++) {
			if (mkdir(dirs[i], 0755) && errno != EEXIST) {
				ok = false;
				break;
			}
		}
		if (ok) {
			hist_file =
			    afmt("%s/.local/share/knot-resolver/" HISTORY_FILE, home);
		}
	} else {
		if (!mkdir(afmt("%s/knot-resolver/", data_home), 0755)
		    || errno == EEXIST) {
			hist_file = afmt("%s/knot-resolver/" HISTORY_FILE, data_home);
		}
	}

	//Load history file
	if (hist_file) {
		history(hist, &ev, H_LOAD, hist_file);
	} else {
		perror("While opening history file");
	}

	while (1) {
		line = el_gets(el, &count);
		if (count > 0) {
			history(hist, &ev, H_ENTER, line);
			size_t msg_len;
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
			if (hist_file) {
				history(hist, &ev, H_SAVE, hist_file);
			}
			free(msg);
		}
	}
	history_end(hist);
	free(hist_file);
	el_end(el);
	if (feof(stdin))
		return 0;
	perror("While reading input");
	return 1;
}

int main(int argc, char **argv)
{
	fprintf(stderr, "Warning! %s is highly experimental, use at own risk.\n", argv[0]);
	fprintf(stderr, "Please tell authors what features you expect from client utility.\n");
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
