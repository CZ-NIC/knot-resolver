
#include "daemon/kxsk/impl.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>

static int ensure_udp_prog(const struct config *cfg)
{
	int ret;

	uint32_t prog_id;
	ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_id, cfg->xsk.xdp_flags);
	if (ret)
		return -abs(ret);
	if (prog_id)
		return bpf_prog_get_fd_by_id(prog_id);

	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall */
	int prog_fd;
	struct bpf_object *obj; // TODO: leak or what?
	ret = bpf_prog_load(cfg->xdp_prog_filename, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (ret) {
		fprintf(stderr, "[kxsk] failed loading BPF program (%s) (%d): %s\n",
			cfg->xdp_prog_filename, ret, strerror(-ret));
		return -abs(ret);
	}

	ret = bpf_set_link_xdp_fd(cfg->ifindex, prog_fd, cfg->xsk.xdp_flags);
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
 * (version before they eliminated qidconf_map) */
static int get_bpf_maps(int prog_fd, struct xsk_socket_info *xsk_info)
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
		if (xsk_info->qidconf_map_fd >= 0 && xsk_info->xsks_map_fd >= 0)
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
			xsk_info->qidconf_map_fd = fd;
			continue;
		}

		if (!strcmp(map_info.name, "xsks_map")) {
			xsk_info->xsks_map_fd = fd;
			continue;
		}

		close(fd);
	}

	if (xsk_info->qidconf_map_fd < 0 || xsk_info->xsks_map_fd < 0) {
		err = -ENOENT;
		close(xsk_info->qidconf_map_fd);
		close(xsk_info->xsks_map_fd);
		xsk_info->qidconf_map_fd = xsk_info->xsks_map_fd = -1;
		goto out_map_ids;
	}

	err = 0; // success!

out_map_ids:
	free(map_ids);
	return err;
}

/** Activate this AF_XDP socket through the BPF maps. */
static int update_bpf_maps(struct xsk_socket_info *xsk_info, int queue_id)
{
	int fd = xsk_socket__fd(xsk_info->xsk);
	int err = bpf_map_update_elem(xsk_info->xsks_map_fd, &queue_id, &fd, 0);
	if (err)
		return err;

	int qid = true;
	err = bpf_map_update_elem(xsk_info->qidconf_map_fd, &queue_id, &qid, 0);
	if (err)
		bpf_map_delete_elem(xsk_info->xsks_map_fd, &queue_id);
	return err;
}
/** Deactivate this AF_XDP socket through the BPF maps. */
static int clear_bpf_maps(struct xsk_socket_info *xsk_info, int queue_id)
{
	int qid = false;
	int err = bpf_map_update_elem(xsk_info->qidconf_map_fd, &queue_id, &qid, 0);
	// Clearing the second map doesn't seem important, but why not.
	bpf_map_delete_elem(xsk_info->xsks_map_fd, &queue_id);
	return err;
}

int kxsk_bpf_setup(const struct config *cfg, struct xsk_socket_info *xsk_info)
{
	int ret = ensure_udp_prog(cfg);
	if (ret >= 0)
		ret = get_bpf_maps(ret, xsk_info);
	if (ret == 0)
		ret = update_bpf_maps(xsk_info, cfg->xsk_if_queue);
	return ret;
}

