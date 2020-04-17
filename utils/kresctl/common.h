#pragma once

#include <stdio.h>

#include "kresconfig.h"

#define PROJECT_NAME    "Knot Resolver"
#define PROGRAM_NAME    "kresctl"
#define PROGRAM_DESC    "control/administration tool"
#define HISTORY_FILE    ".kresctl_history"
#define SPACE           "  "


inline static void print_version()
{
	printf("%s (%s), version %s\n", PROGRAM_NAME, PROJECT_NAME, PACKAGE_VERSION);
}