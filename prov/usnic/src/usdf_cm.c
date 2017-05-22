/*
 * Copyright (c) 2014-2016, Cisco Systems, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <asm/types.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>
#include "fi.h"
#include "fi_file.h"

#include "usnic_direct.h"
#include "usdf.h"
#include "usdf_endpoint.h"
#include "usdf_dgram.h"
#include "usdf_av.h"
#include "usdf_cm.h"

void
usdf_cm_msg_connreq_cleanup(struct usdf_connreq *crp)
{
	struct usdf_ep *ep;
	struct usdf_pep *pep;
	struct usdf_fabric *fp;

	ep = crp->cr_ep;
	pep = crp->cr_pep;
	if (pep != NULL) {
		fp = pep->pep_fabric;
	} else {
		fp = ep->ep_domain->dom_fabric;
	}

	if (crp->cr_pollitem.pi_rtn != NULL) {
		(void) epoll_ctl(fp->fab_epollfd, EPOLL_CTL_DEL, crp->cr_sockfd, NULL);
		crp->cr_pollitem.pi_rtn = NULL;
	}
	if (crp->cr_sockfd != -1) {
		close(crp->cr_sockfd);
		crp->cr_sockfd = -1;
	}

	/* If there is a passive endpoint, recycle the crp */
	if (pep != NULL) {
		if (TAILQ_ON_LIST(crp, cr_link)) {
			TAILQ_REMOVE(&pep->pep_cr_pending, crp, cr_link);
		}
		TAILQ_INSERT_TAIL(&pep->pep_cr_free, crp, cr_link);
	} else {
		free(crp);
	}
}

/* Given a connection request structure containing data, make a copy of the data
 * that can be accessed in error entries on the EQ. The return value is the size
 * of the data stored in the error entry. If the return value is a non-negative
 * value, then the function has suceeded and the size and output data can be
 * assumed to be valid. If the function fails, then the data will be NULL and
 * the size will be a negative error value.
 */
static int usdf_cm_generate_err_data(struct usdf_eq *eq,
		struct usdf_connreq *crp, void **data)
{
	struct usdf_err_data_entry *err_data_entry;
	struct usdf_connreq_msg *reqp;
	size_t entry_size;
	size_t data_size;

	if (!eq || !crp || !data) {
		USDF_DBG_SYS(EP_CTRL,
				"eq, crp, or data is NULL.\n");
		return -FI_EINVAL;
	}

	/* Initialize to NULL so data can't be used in the error case. */
	*data = NULL;

	reqp = (struct usdf_connreq_msg *) crp->cr_data;

	/* This is a normal case, maybe there was no data. */
	if (!reqp || !reqp->creq_datalen)
		return 0;

	data_size = reqp->creq_datalen;

	entry_size = sizeof(*err_data_entry) + data_size;

	err_data_entry = calloc(1, entry_size);
	if (!err_data_entry) {
		USDF_WARN_SYS(EP_CTRL,
				"failed to allocate err data entry\n");
		return -FI_ENOMEM;
	}

	/* This data should be copied and owned by the provider. Keep
	 * track of it in the EQ, this will be freed in the next EQ read
	 * call after it has been read.
	 */
	memcpy(err_data_entry->err_data, reqp->creq_data, data_size);
	slist_insert_tail(&err_data_entry->entry, &eq->eq_err_data);

	*data = err_data_entry->err_data;

	return data_size;
}

/* Report a connection management related failure. Sometimes there is connection
 * event data that should be copied into the generated event. If the copy_data
 * parameter evaluates to true, then the data will be copied.
 *
 * If data is to be generated for the error entry, then the connection request
 * is assumed to have the data size in host order. If something fails during
 * processing of the error data, then the EQ entry will still be generated
 * without the error data.
 */
void usdf_cm_report_failure(struct usdf_connreq *crp, int error, bool copy_data)
{
	struct fi_eq_err_entry err = {0};
        struct usdf_pep *pep;
        struct usdf_ep *ep;
        struct usdf_eq *eq;
	fid_t fid;
	int ret;

	USDF_DBG_SYS(EP_CTRL, "error=%d (%s)\n", error, fi_strerror(error));

        pep = crp->cr_pep;
        ep = crp->cr_ep;

	if (ep != NULL) {
		fid = ep_utofid(ep);
		eq = ep->ep_eq;
		ep->ep_domain->dom_peer_tab[ep->e.msg.ep_rem_peer_id] = NULL;
	} else {
		fid = pep_utofid(pep);
		eq = pep->pep_eq;
	}

	/* Try to generate the space necessary for the error data. If the
	 * function returns a number greater than or equal to 0, then it was a
	 * success. The return value is the size of the data.
	 */
	if (copy_data) {
		ret = usdf_cm_generate_err_data(eq, crp, &err.err_data);
		if (ret >= 0)
			err.err_data_size = ret;
	}

        err.fid = fid;
        err.err = -error;

        usdf_eq_write_internal(eq, 0, &err, sizeof(err), USDF_EVENT_FLAG_ERROR);

        usdf_cm_msg_connreq_cleanup(crp);
}

int usdf_cm_dgram_getname(fid_t fid, void *addr, size_t *addrlen)
{
	int ret;
	struct usdf_ep *ep;
	struct sockaddr_in sin;
	socklen_t slen;
	size_t copylen;

	USDF_TRACE_SYS(EP_CTRL, "\n");

	ep = ep_fidtou(fid);

	copylen = MIN(sizeof(sin), *addrlen);
	*addrlen = sizeof(sin);

	memset(&sin, 0, sizeof(sin));
	if (ep->e.dg.ep_qp == NULL) {
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr =
			ep->ep_domain->dom_fabric->fab_dev_attrs->uda_ipaddr_be;
		sin.sin_port = 0;
	} else {
		slen = sizeof(sin);
		ret = getsockname(ep->e.dg.ep_sock, (struct sockaddr *)&sin, &slen);
		if (ret == -1) {
			return -errno;
		}
		assert(((struct sockaddr *)&sin)->sa_family == AF_INET);
		assert(slen == sizeof(sin));
		assert(sin.sin_addr.s_addr ==
			ep->ep_domain->dom_fabric->fab_dev_attrs->uda_ipaddr_be);
	}
	memcpy(addr, &sin, copylen);

	if (copylen < sizeof(sin))
		return -FI_ETOOSMALL;
	else
		return 0;
}

/* Checks that the given address is actually a sockaddr_in of appropriate
 * length.  "addr_format" is an FI_ constant like FI_SOCKADDR_IN indicating the
 * claimed type of the given address.
 *
 * Returns true if address is actually a sockaddr_in, false otherwise.
 *
 * Upon successful return, "addr" can be safely cast to either
 * "struct sockaddr_in *" or "struct sockaddr *".
 *
 * "addr" should not be NULL.
 */
bool usdf_cm_addr_is_valid_sin(void *addr, size_t addrlen, uint32_t addr_format)
{
	assert(addr != NULL);

	switch (addr_format) {
	case FI_SOCKADDR_IN:
	case FI_SOCKADDR:
		if (addrlen != sizeof(struct sockaddr_in)) {
			USDF_WARN("addrlen is incorrect\n");
			return false;
		}
		if (((struct sockaddr *)addr)->sa_family != AF_INET) {
			USDF_WARN("unknown/unsupported addr_format\n");
			return false;
		}
		return true;
	default:
		USDF_WARN("unknown/unsupported addr_format\n");
		return false;
	}
}
