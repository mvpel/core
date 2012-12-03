/* 
   Copyright (C) Cfengine AS

   This file is part of Cfengine 3 - written and maintained by Cfengine AS.
 
   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; version 3.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
  You should have received a copy of the GNU General Public License  
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA

  To the extent this program is licensed as part of the Enterprise
  versions of Cfengine, the applicable Commerical Open Source License
  (COSL) may apply to this file if you as a licensee so wish it. See
  included file COSL.txt.

*/

/*
 * This file is a derivative work of the following part of SIGAR:
 *   cpansearch.perl.org/src/DOUGM/hyperic-sigar-1.6.3-src/src/os/hpux/dlpi.c
 * which is Copyright (C) [2004, 2005, 2006], Hyperic, Inc.
 * 
 * SIGAR is free software; you can redistribute it and/or modify
 * it under the terms version 2 of the GNU General Public License as
 * published by the Free Software Foundation. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 * 
 */

/* 
 * talk to Data Link Provider Interface aka /dev/dlpi
 * see: http://docs.hp.com/hpux/onlinedocs/B2355-90139/B2355-90139.html
 */

#include "cf3.defs.h"
#include "vars.h"
#include "files_names.h"
#include "env_context.h"

/* We deactivate this entire file if we are on a non-DLPI platform */
#ifdef HAVE_SYS_DLPI_H
#include <sys/dlpi.h>

#ifdef HAVE_SYS_DLPI_EXT_H	/* HP-UX extensions for DLPI */
#include <sys/dlpi_ext.h>
#endif 

#include <sys/stropts.h>

#define	DLBUF_SIZE 8192
#define ERRBUF_SIZE 1024

static int send_req(int fd, char *ptr, int len, char *what, char *ebuf)
{
    struct strbuf ctl;
    int flags = 0;

    ctl.maxlen = 0;
    ctl.len    = len;
    ctl.buf    = ptr;

    if (putmsg(fd, &ctl, (struct strbuf *) NULL, flags) < 0) {
        snprintf(ebuf, ERRBUF_SIZE, "send_req: putmsg \"%s\": %s",
                 what, strerror(errno));
        return -1;
    }

    return 0;
}

static int recv_ack(int fd, int size, const char *what, char *bufp, char *ebuf)
{
    union DL_primitives *dlp;
    struct strbuf ctl;
    int flags = 0;

    ctl.maxlen = DLBUF_SIZE;
    ctl.len    = 0;
    ctl.buf    = bufp;

    if (getmsg(fd, &ctl, (struct strbuf*)NULL, &flags) < 0) {
        snprintf(ebuf, ERRBUF_SIZE, "recv_ack: %s getmsg: %s",
                 what, strerror(errno));
        return -1;
    }

    dlp = (union DL_primitives *)ctl.buf;
    switch (dlp->dl_primitive) {
      case DL_INFO_ACK:
      case DL_BIND_ACK:
      case DL_OK_ACK:
      case DL_HP_PPA_ACK:	// Only this is used for now, Solaris later?
      case DL_HP_INFO_ACK:
      case DL_GET_STATISTICS_ACK:
        break;

      case DL_ERROR_ACK:
        switch (dlp->error_ack.dl_errno) {

          case DL_SYSERR:
            snprintf(ebuf, ERRBUF_SIZE, "recv_ack: %s: system error - %s",
                     what, strerror(dlp->error_ack.dl_unix_errno));
            break;

          default:
            snprintf(ebuf, ERRBUF_SIZE, "recv_ack: %s: dl error - %d",
                     what, dlp->error_ack.dl_errno);
            break;
        }
        return -1;
      default:
        snprintf(ebuf, ERRBUF_SIZE,
                 "recv_ack: %s: unexpected primitive ack %d",
                 what, dlp->dl_primitive);
        return -1;
    }

    if (ctl.len < size) {
        snprintf(ebuf, ERRBUF_SIZE,
                 "recv_ack: %s: ack too small (%d < %d)",
                 what, ctl.len, size);
        return -1;
    }

    return ctl.len;
}

/* Wrapper functions for specific types of DLPI requests, based on SIGAR. */
static int dl_hp_ppa_req(int fd, char *ebuf)
{
    dl_hp_ppa_req_t req;

    req.dl_primitive = DL_HP_PPA_REQ;

    return send_req(fd, (char *)&req, sizeof(req), "hp_ppa", ebuf);
}

static int dl_hp_ppa_ack(int fd, char *bufp, char *ebuf)
{
    return recv_ack(fd, DL_HP_PPA_ACK_SIZE, "hp_ppa", bufp, ebuf);
}

/*************************************************************/
/* The code below was written for CFEngine Community Edition */
/* and is not part of SIGAR.                                 */
/*************************************************************/

// Convert a series of bytes to text in colon-delimited MAC address format.
// Since Infiniband MAC addresses are 20 octets, we don't assume EUI-48
// six bytes for Ethernet. It might also be a disk's 16-byte World Wide Name.
// Remember to free() the returned MAC string when no longer needed.
// This function should be moved to unix.c, actually, since it's not DLPI.
char *rawmac_to_text(u_char *rawmac, unsigned int len) {
	char *textmac;
        u_char i;

	if (len == 0 || len > 20)
		return NULL;

	textmac = xmalloc(len * 3);
	for (i = 0 ; i < len; i++) {
		sprintf(textmac + i * 3, "%02x:", rawmac[i]);
	}
	*(textmac + len * 3 - 1) = 0;
	return(textmac);
}

#ifdef HAVE_SYS_DLPI_EXT_H
// Use the HP Data Link Provider Interface (DLPI) extensions to enumerate all
// Physical Points of Attachment (PPAs) and find their MAC addresses.
void GetMacAddress_HPUX(enum cfagenttype ag,
		Rlist **interfaces, Rlist **hardware) {
	int fd;
	char ebuf[ERRBUF_SIZE];
	uint32_t buf[DLBUF_SIZE / sizeof(uint32_t)];
	dl_hp_ppa_ack_t *ppa_ack;
	dl_hp_ppa_info_t *ppa_info, *ppa_info_1;
	char *hw_mac, ifname[CF_SMALLBUF];
	char name[CF_MAXVARSIZE];

	/* Open the HP DLPI device */
	if ((fd = open("/dev/dlpi", O_RDWR)) == -1) {
		CfOut(cf_error, "open",
			"Could not open /dev/dlpi to query net interfaces: %s",
				strerror(errno));
		return;
	}
 
	if (dl_hp_ppa_req(fd, ebuf) < 0
			|| dl_hp_ppa_ack(fd, (char *)buf, ebuf) < 0) {
        	close(fd);
		CfOut(cf_error, "dlpi", "%s", ebuf);
		return;
	}
        close(fd);
	ppa_ack = (dl_hp_ppa_ack_t *)buf;

	/* Make sure we found at least one PPA */
	if (ppa_ack->dl_length == 0) {
		CfOut(cf_inform, "dlpi",
			"No physical network interfaces found");
		return;
	}

	// Point to the offset of the first PPA info structure in the ack
	ppa_info = ppa_info_1 = (dl_hp_ppa_info_t *)((u_char *)buf +
							ppa_ack->dl_offset);
        do {
		// If the interface is marked dead, skip it
		if ( ppa_info->dl_hdw_state & HDW_DEAD) {
			continue;
		}

		// Get the MAC and its length, and convert to text
		hw_mac = rawmac_to_text(ppa_info->dl_phys_addr,
						ppa_info->dl_addr_length);

		// Populate the variables & classes
		snprintf(ifname, CF_SMALLBUF, "%s%d", ppa_info->dl_module_id_1,
			ppa_info->dl_instance_num);
		AppendRlist(interfaces, ifname, CF_SCALAR);
		AppendRlist(hardware, hw_mac, CF_SCALAR);
		snprintf(name, CF_MAXVARSIZE, "mac_%s", CanonifyName(hw_mac));
		NewClass(name);

		snprintf(name, CF_MAXVARSIZE, (ag != cf_know)
					? "hardware_mac[%s]"
					: "hardware_mac[interface_name]",
				ifname);
		NewScalar("sys", name, hw_mac, cf_str);

		// If we want to add a new $(sys.interface_mtu[lan0]) array:
		//snprintf(name, CF_MAXVARSIZE, (ag != cf_know)
		//			? "interface_mtu[%s]"
		//			: "interface_mtu[interface_name]",
		//		ifname);
		//snprintf(ifname, CF_SMALLBUF, "%d", (int)ppa_info->dl_mtu);
		//NewScalar("sys", name, ifname, cf_int);

		free(hw_mac);
	} while (ppa_info->dl_next_offset &&
			(ppa_info = (dl_hp_ppa_info_t *)((u_char *)ppa_info_1
					+ ppa_info->dl_next_offset)));
	// Note that dl_next_offset is from the start of the whole info result,
	// rather than the start of the current info record. 
	// Some DLPI documentation is vague on this point; avoid mistakes!
}
#endif /* HAVE_SYS_DLPI_EXT_H */

// Solaris DLPI interface probes can be added here and at the end of
// GetMacAddress() in unix.c, if needed. They should be able to use the
// same DLPI functions.

#endif /* HAVE_SYS_DLPI_H */
