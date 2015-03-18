/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <libknot/internal/mempool.h>

#include "daemon/cmd.h"
#include "lib/defines.h"

struct cmd {
	const char *name;
	int (*cb)(struct worker_ctx *, char *);
};

static int help(struct worker_ctx *worker, char *args)
{
	printf("help:\n    show this help\n");
	printf("context:\n    show context information\n");
	printf("load:\n    load module\n");
	printf("unload:\n    unload module\n");

	struct kr_context *ctx = &worker->resolve;
	for (unsigned i = 0; i < ctx->mod_loaded; ++i) {
		struct kr_module *mod = &ctx->modules[i];
		for (struct kr_prop *p = mod->props; p && p->name; ++p) {
			printf("%s.%s:\n    %s\n", mod->name, p->name, p->info);
		}
	}

	return kr_ok();
}

static int context(struct worker_ctx *worker, char *args)
{
	struct kr_context *ctx = &worker->resolve;

	/* Modules */
	printf("modules:\n");
	for (unsigned i = 0; i < ctx->mod_loaded; ++i) {
		struct kr_module *mod = &ctx->modules[i];
		printf("    %s\n", mod->name);
	}
	/* Options */
	printf("options: 0x%x\n", ctx->options);

	return kr_ok();
}

static int mod_load(struct worker_ctx *worker, char *args)
{
	struct kr_context *ctx = &worker->resolve;
	char *saveptr = NULL;
	char *prop_name = strtok_r(args, " \t\n\r", &saveptr);
	return kr_context_register(ctx, prop_name);
}

static int mod_unload(struct worker_ctx *worker, char *args)
{
	return kr_error(ENOTSUP);
}

static int cmd_exec_prop(struct worker_ctx *worker, char *name, char *prop, char *args)
{
	struct kr_context *ctx = &worker->resolve;

	for (unsigned i = 0; i < ctx->mod_loaded; ++i) {
		struct kr_module *mod = &ctx->modules[i];
		if (strncmp(mod->name, name, strlen(mod->name)) != 0) {
			continue;
		}
		for (struct kr_prop *p = mod->props; p && p->name; ++p) {
			if (strncmp(p->name, prop, strlen(p->name)) == 0) {
				auto_free char *res = p->cb(ctx, mod, args);
				printf("%s\n", res);
				return kr_ok();
			}
		}
	}

	return kr_error(ENOENT);
}

int cmd_exec(struct worker_ctx *worker, char *cmd)
{
	static struct cmd cmd_table[] = {
		{ "help", &help },
		{ "context", &context },
		{ "load", &mod_load },
		{ "unload", &mod_unload },
		{ NULL, NULL }
	};

	int ret = kr_error(ENOENT);
	char *args = strchr(cmd, ' ');
	if (args != NULL) {
		*args = '\0';
		args += 1;
	}

	/* Search builtin namespace. */
	for (struct cmd *c = cmd_table; c->name; ++c) {
		if (strncmp(cmd, c->name, strlen(c->name)) == 0) {
			return c->cb(worker, args);
		}
	}

	/* Search module namespace. */
	char *prop = strchr(cmd, '.');
	if (prop != NULL) {
		ret = cmd_exec_prop(worker, cmd, prop + 1, args);

	}

	return ret;
}