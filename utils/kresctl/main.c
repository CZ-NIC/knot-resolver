#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "kresconfig.h"
#include "common.h"
#include "interactive.h"
#include "process.h"
#include "commands.h"


params_t params = {};

static void print_help(void)
{
    print_version();
    printf("\nUsage:\n"
           SPACE"%s [parameters] <command> [command_arguments]\n"
           "\n"
           "Parameters:\n"
           " -h, --help               "SPACE"Print the program help.\n"
           " -V, --version            "SPACE"Print the program version.\n",
           PROGRAM_NAME);
    print_commands();
}

int main(int argc, char *argv[])
{
    /* Long options. */
    struct option opts[] = {
        { "help",    no_argument, NULL, 'h' },
        { "version", no_argument, NULL, 'V' },
        { NULL }
    };

    // TODO: here generate dynamic commands from yang schema

    /* Parse command line parameters */
    int opt = 0;
    while ((opt = getopt_long(argc, argv, "hV", opts, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_help();
                return EXIT_SUCCESS;
            case 'V':
                print_version(PROGRAM_NAME);
                return EXIT_SUCCESS;
            default:
                print_help();
                return EXIT_FAILURE;
        }
    }

    int ret;
    if (argc - optind < 1) {
        ret = interactive_loop(&params);
    } else {
        ret = process_cmd(argc - optind, (const char **)argv + optind, &params);
    }

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}