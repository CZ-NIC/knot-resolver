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
