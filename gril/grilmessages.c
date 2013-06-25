/*
 *
 *  RIL library with GLib integration
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *  Copyright (C) 2012-2013  Canonical Ltd.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/gprs-context.h>

#include "gril.h"
#include "grilmessages.h"
#include "parcel.h"
#include "ril_constants.h"

/* SETUP_DATA_CALL_PARAMS request params */
#define SETUP_DATA_CALL_PARAMS 7
#define DATA_PROFILE_DEFAULT_STR "0"
#define DATA_PROFILE_TETHERED_STR "1"
#define DATA_PROFILE_OEM_BASE_STR "1000"
#define PROTO_IP_STR "IP"
#define PROTO_IPV6_STR "IPV6"
#define PROTO_IPV4V6_STR "IPV4V6"

/* SETUP_DATA_CALL_PARAMS reply params */
#define MIN_DATA_CALL_REPLY_SIZE 36

/*
 * TODO:
 *
 * 1. It might be a better idea to split this file into
 * three separate files, grilrequests, grilreplies, and
 * grilevents.
 *
 * 2. A potential future change here is to create a driver
 * abstraction for each request/reply/event method, and a
 * corresponding method to allow new per-message implementations
 * to be registered.  This would allow PES to easily add code
 * to quirk a particular RIL implementation.
 *
 * struct g_ril_messages_driver {
 *	const char *name;
 * };
 *
 */
gboolean g_ril_setup_data_call(GRil *gril,
				const struct setup_data_call_req *request,
				struct parcel *rilp, struct ofono_error *error)
{
	gchar *protocol_str;
	gchar tech_str[3];
	gchar *auth_str[2];
	gchar *profile_str;

	if (request->tech < RADIO_TECH_GPRS || request->tech > RADIO_TECH_GSM) {
		error->type = OFONO_ERROR_TYPE_FAILURE;
		error->error = -EINVAL;
		return FALSE;
	}

	switch (request->data_profile) {
	case RIL_DATA_PROFILE_DEFAULT:
		profile_str = DATA_PROFILE_DEFAULT_STR;
		break;
	case RIL_DATA_PROFILE_TETHERED:
		profile_str = DATA_PROFILE_TETHERED_STR;
		break;
	case RIL_DATA_PROFILE_OEM_BASE:
		profile_str = DATA_PROFILE_OEM_BASE_STR;
		break;
	default:
		error->type = OFONO_ERROR_TYPE_FAILURE;
		error->error = -EINVAL;
		return FALSE;
	}

	if (request->apn == NULL || strlen(request->apn) == 0) {
		error->type = OFONO_ERROR_TYPE_FAILURE;
		error->error = -EINVAL;
		return FALSE;
	}

	if (request->auth_type < RIL_AUTH_NONE || request->auth_type > RIL_AUTH_BOTH) {
		error->type = OFONO_ERROR_TYPE_FAILURE;
		error->error = -EINVAL;
		return FALSE;
	}

	switch (request->protocol) {
	case OFONO_GPRS_PROTO_IPV6:
		protocol_str = PROTO_IPV6_STR;
		break;
	case OFONO_GPRS_PROTO_IPV4V6:
		protocol_str = PROTO_IPV4V6_STR;
		break;
	case OFONO_GPRS_PROTO_IP:
		protocol_str = PROTO_IP_STR;
		break;
	default:
		error->type = OFONO_ERROR_TYPE_FAILURE;
		error->error = -EINVAL;
		return FALSE;
	}

	g_print("About to write num params\n");

	parcel_w_int32(rilp, SETUP_DATA_CALL_PARAMS);

	sprintf((char *) tech_str, "%d", request->tech);
	parcel_w_string(rilp, (char *) tech_str);
	parcel_w_string(rilp, (char *) profile_str);
	parcel_w_string(rilp, (char *) request->apn);
	parcel_w_string(rilp, (char *) request->username);
	parcel_w_string(rilp, (char *) request->password);

	g_print("About to set auth_type %d\n", request->auth_type);

	sprintf((char *) auth_str, "%d", request->auth_type);

	g_print("auth_str is %s\n", auth_str);
	parcel_w_string(rilp, (char *) auth_str);
	parcel_w_string(rilp, (char *) protocol_str);

	g_print("About to call append_print_buf\n");
	/* ...or this could go in the calling function,
	 * which means we'd get rid of the *request param */
	g_ril_append_print_buf(gril,
				"(%s,%s,%s,%s,%s,%s,%s)",
				tech_str,
				profile_str,
				request->apn,
				request->username,
				request->password,
				auth_str,
				protocol_str);

	return TRUE;
}


/* TODO: create data_call_reply a struct to reduce params */
gboolean g_ril_parse_data_call_reply(GRil *gril,
					struct setup_data_call_reply *reply,
					struct parcel *rilp,
					struct ofono_error *error)
{
	int version, num, retry_time, active;
	char *dnses = NULL, *ifname = NULL;
	char *raw_ip_addrs = NULL, *raw_gws = NULL, *type = NULL;

	/* TODO:
	 * Cleanup duplicate code between this function and
	 * ril_util_parse_data_call_list().
	 */

	/* valid size: 36 (34 if HCRADIO defined) */
	if (rilp->size < MIN_DATA_CALL_REPLY_SIZE) {
		error->type = OFONO_ERROR_TYPE_FAILURE;
		error->error = -EINVAL;
		goto error;
	}

	/*
	 * ril.h documents the reply to a RIL_REQUEST_SETUP_DATA_CALL
	 * as being a RIL_Data_Call_Response_v6 struct, however in
	 * reality, the response actually includes the version of the
	 * struct, followed by an array of calls, so the array size
	 * also has to be read after the version.
	 *
	 * TODO: What if there's more than 1 call in the list??
	 */

	/*
	 * TODO: consider using 'unused' variable; however if we
	 * do this, the alternative is a few more append_print_buf
	 * calls ( which become no-ops if tracing isn't enabled.
	 */
	version = parcel_r_int32(rilp);
	num = parcel_r_int32(rilp);
	if (num != 8) {
		error->type = OFONO_ERROR_TYPE_FAILURE;
		error->error = -EINVAL;
		goto error;
	}

	reply->status = parcel_r_int32(rilp);
	retry_time = parcel_r_int32(rilp);
	reply->cid = parcel_r_int32(rilp);
	active = parcel_r_int32(rilp);
	type = parcel_r_string(rilp);
	reply->ifname = parcel_r_string(rilp);
	raw_ip_addrs = parcel_r_string(rilp);
	dnses = parcel_r_string(rilp);
	raw_gws = parcel_r_string(rilp);

	g_ril_append_print_buf(gril,
				"{version=%d,num=%d [status=%d,retry=%d,cid=%d,active=%d,type=%s,ifname=%s,address=%s,dns=%s,gateways=%s]}",
				version,
				num,
				reply->status,
				retry_time,
				reply->cid,
				active,
				type,
				ifname,
				raw_ip_addrs,
				dnses,
				raw_gws);

	/* TODO:
	 * RILD can return multiple addresses; oFono only supports
	 * setting a single IPv4 address.  At this time, we only
	 * use the first address.  It's possible that a RIL may
	 * just specify the end-points of the point-to-point
	 * connection, in which case this code will need to
	 * changed to handle such a device.
	 *
	 * For now split into a maximum of three, and only use
	 * the first address for the remaining operations.
	 */
	reply->ip_addrs = g_strsplit(raw_ip_addrs, " ", 3);
	if (reply->ip_addrs[0] == NULL) {
		DBG("No IP address specified: %s", raw_ip_addrs);

		/* TODO: make this a macro! */
		error->type = OFONO_ERROR_TYPE_FAILURE;
		error->error = -EINVAL;
		goto error;
	}

	/*
	 * RILD can return multiple addresses; oFono only supports
	 * setting a single IPv4 gateway.
	 */
	reply->gateways = g_strsplit(raw_gws, " ", 3);
	if (reply->gateways[0] == NULL) {
		DBG("Invalid gateways field returned: %s", raw_gws);

		/* TODO: make this a macro! */
		error->type = OFONO_ERROR_TYPE_FAILURE;
		error->error = -EINVAL;
		goto error;
	}

	/* Split DNS addresses */
	reply->dns_addresses = g_strsplit(dnses, " ", 3);

	error->type = OFONO_ERROR_TYPE_NO_ERROR;
	error->error = 0;
	return TRUE;

error:
	g_strfreev(reply->dns_addresses);
	g_strfreev(reply->ip_addrs);
	g_strfreev(reply->gateways);

	g_free(type);
	g_free(reply->ifname);
	g_free(raw_ip_addrs);
	g_free(dnses);
	g_free(raw_gws);

	return FALSE;
}


