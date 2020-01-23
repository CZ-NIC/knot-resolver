#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <lua.h>
#include <sysrepo.h>


typedef struct conversion_row conversion_row_t;

struct conversion_row {
	const char * xpath;
	/* set configuration functions
		1. prepare value on xpath for Lua function and then push it to Lua stack
		2. execute Lua function with previously pushed parameters result save on top of Lua stack
		3. get result from top of Lua stack, parse and validate it => SR_ERR_OK
	 */

	/* get configuration functions
		1. prepare parametrs based on xpath for Lua function to get configured value and push it to top of Lua stack
		2. execute Lua function with previously pushed parameters result save on top of Lua stack
		3. get result from top of Lua stack, convert it to type on xpath and push it to sysrepo
	 */

	/* dlete configuration functions
		1. prepare parameters based on xpath for Lua function to delete configuration, push on top of Lua stack
		2. execute Lua function to delete config, result save to top of Lua stack
		3. read result from Lua stack and confirm if it was successfull
	 */
};
