/*  Copyright (C) 2018 Cloudflare, Inc.

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

#pragma once

#include <uv.h>

/**
 * Parse v1 and v2 headers of the PROXY protocol defined at
 * https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
 *
 * If the data read in the buffer does not have a PROXY protocol header, this
 * function returns kr_ok() without any changes to its inputs.
 * If there is a correct header, handle->data is updated accordingly and
 * nread/buf are modified to make it look like there was no header present.
 * kr_ok() is then returned.
 * If there is a malformed header, return kr_error(EINVAL).
 * @param handle socket through which the request came
 * @param nread  the number of bytes read
 * @param buf    buffer which the bytes that were read
 * @return kr_ok() or kr_error(EINVAL)
 */
int proxy_protocol_parse(uv_handle_t *handle, ssize_t *nread, uv_buf_t *buf);
