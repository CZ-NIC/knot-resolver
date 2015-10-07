/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <uv.h>
#include <libknot/packet/pkt.h>

int udp_bind(uv_udp_t *handle, struct sockaddr *addr);
int tcp_bind(uv_tcp_t *handle, struct sockaddr *addr);
void io_create(uv_loop_t *loop, uv_handle_t *handle, int type);
int io_start_read(uv_handle_t *handle);
int io_stop_read(uv_handle_t *handle);