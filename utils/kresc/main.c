/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <getopt.h>
#include <stdio.h>

#include "interactive.h"
#include "process.h"
#include "utils/common/sysrepo_conf.h"


static void print_help(void)
{
	printf("%s (Knot Resolver) control/config tool\n"
		   "\n"
		   "Usage:\n"
	       SPACE"%s [parameters] <command> [command_args]\n"
	       "\n"
	       "Parameters:\n"
		   SPACE"no parameter              Interactive mode\n"
	       SPACE"-h, --help                Print the program help.\n"
	       SPACE"-V, --version             Print the program version.\n",
	       PROGRAM_NAME, PROGRAM_NAME);

	printf("\nCommands:\n");

	print_commands_help();
}

params_t params = {
};

int main(int argc, char *argv[])
{
	struct option opts[] = {
		{ "help",          no_argument,       NULL, 'h' },
		{ "version",       no_argument,       NULL, 'V' },
		{ NULL }
	};	

	int opt = 0;
	while ((opt = getopt_long(argc, argv, "+hV", opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			print_help();
			goto cleanup;
		case 'V':
			print_version();
			goto cleanup;
		default:
			print_help();
			goto cleanup;
		}
	}

	int ret;
	if (argc - optind < 1) {
		ret = interactive_loop(&params);
	} else {
		ret = process_cmd(argc - optind, (const char **)argv + optind, &params);
	}

	cleanup:
	return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
