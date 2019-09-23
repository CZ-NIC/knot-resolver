
#include "daemon/kxsk/impl.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <net/if.h>


static int ensure_udp_prog(const struct kxsk_iface *iface, const char *prog_fname)
{
	int ret;

	uint32_t prog_id;
	ret = bpf_get_link_xdp_id(iface->ifindex, &prog_id, 0);
	if (ret)
		return -abs(ret);
	if (prog_id)
		return bpf_prog_get_fd_by_id(prog_id);

	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall */
	int prog_fd;
	struct bpf_object *obj; // TODO: leak or what?
	ret = bpf_prog_load(prog_fname, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (ret) {
		fprintf(stderr, "[kxsk] failed loading BPF program (%s) (%d): %s\n",
			prog_fname, ret, strerror(-ret));
		return -abs(ret);
	}

	ret = bpf_set_link_xdp_fd(iface->ifindex, prog_fd, 0);
	if (ret) {
		fprintf(stderr, "bpf_set_link_xdp_fd() == %d\n", ret);
		return -abs(ret);
	} else {
		fprintf(stderr, "[kxsk] loaded BPF program\n");
	}

	return prog_fd;
}

/** Get FDs for the two maps and assign them into xsk_info-> fields.
 *
 * It's almost precise copy of xsk_lookup_bpf_maps() from libbpf
 * (version before they eliminated qidconf_map)
 * Copyright by Intel, LGPL-2.1 or BSD-2-Clause. */
static int get_bpf_maps(int prog_fd, struct kxsk_iface *iface)
{
	__u32 i, *map_ids, num_maps, prog_len = sizeof(struct bpf_prog_info);
	__u32 map_len = sizeof(struct bpf_map_info);
	struct bpf_prog_info prog_info = {};
	struct bpf_map_info map_info;
	int fd, err;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err)
		return err;

	num_maps = prog_info.nr_map_ids;

	map_ids = calloc(prog_info.nr_map_ids, sizeof(*map_ids));
	if (!map_ids)
		return -ENOMEM;

	memset(&prog_info, 0, prog_len);
	prog_info.nr_map_ids = num_maps;
	prog_info.map_ids = (__u64)(unsigned long)map_ids;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err)
		goto out_map_ids;

	for (i = 0; i < prog_info.nr_map_ids; ++i) {
		if (iface->qidconf_map_fd >= 0 && iface->xsks_map_fd >= 0)
			break;

		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0)
			continue;

		err = bpf_obj_get_info_by_fd(fd, &map_info, &map_len);
		if (err) {
			close(fd);
			continue;
		}

		if (!strcmp(map_info.name, "qidconf_map")) {
			iface->qidconf_map_fd = fd;
			continue;
		}

		if (!strcmp(map_info.name, "xsks_map")) {
			iface->xsks_map_fd = fd;
			continue;
		}

		close(fd);
	}

	if (iface->qidconf_map_fd < 0 || iface->xsks_map_fd < 0) {
		err = -ENOENT;
		close(iface->qidconf_map_fd);
		close(iface->xsks_map_fd);
		iface->qidconf_map_fd = iface->xsks_map_fd = -1;
		goto out_map_ids;
	}

	err = 0; // success!

out_map_ids:
	free(map_ids);
	return err;
}
static void unget_bpf_maps(struct kxsk_iface *iface)
{
	close(iface->qidconf_map_fd);
	close(iface->xsks_map_fd);
	iface->qidconf_map_fd = iface->xsks_map_fd = -1;
}

int kxsk_socket_start(const struct kxsk_iface *iface, int queue_id, struct xsk_socket *xsk)
{
	int fd = xsk_socket__fd(xsk);
	int err = bpf_map_update_elem(iface->xsks_map_fd, &queue_id, &fd, 0);
	if (err)
		return err;

	int qid = true;
	err = bpf_map_update_elem(iface->qidconf_map_fd, &queue_id, &qid, 0);
	if (err)
		bpf_map_delete_elem(iface->xsks_map_fd, &queue_id);
	return err;
}
int kxsk_socket_stop(const struct kxsk_iface *iface, int queue_id)
{
	int qid = false;
	int err = bpf_map_update_elem(iface->qidconf_map_fd, &queue_id, &qid, 0);
	// Clearing the second map doesn't seem important, but why not.
	bpf_map_delete_elem(iface->xsks_map_fd, &queue_id);
	return err;
}

struct kxsk_iface * kxsk_iface_new(const char *ifname, const char *prog_fname)
{
	struct kxsk_iface *iface = malloc(sizeof(*iface));
	if (!iface) {
		errno = ENOMEM;
		return NULL;
	}
	iface->ifname = ifname; // we strdup it later
	iface->ifindex = if_nametoindex(ifname);
	if (!iface->ifindex) {
		free(iface);
		return NULL;
	}
	iface->qidconf_map_fd = iface->xsks_map_fd = -1;

	int ret = ensure_udp_prog(iface, prog_fname);
	if (ret >= 0)
		ret = get_bpf_maps(ret, iface);

	if (ret < 0) {
		errno = abs(ret);
		free(iface);
		return NULL;
	} // else

	iface->ifname = strdup(iface->ifname);
	return iface;
}
int kxsk_iface_free(struct kxsk_iface *iface, bool unload_bpf)
{
	unget_bpf_maps(iface);
	if (unload_bpf) {
		int ret = bpf_set_link_xdp_fd(iface->ifindex, -1, 0);
		if (ret) return ret;
	}
	free((char *)/*const-cast*/iface->ifname);
	free(iface);
	return 0;
}

