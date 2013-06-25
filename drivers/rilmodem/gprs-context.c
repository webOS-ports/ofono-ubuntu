/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *  Copyright (C) 2013 Canonical Ltd.
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

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/gprs-context.h>
#include <ofono/types.h>

#include "gril.h"
#include "grilmessages.h"
#include "grilutil.h"

#include "rilmodem.h"

/* REQUEST_DEACTIVATE_DATA_CALL parameter values */
#define DEACTIVATE_DATA_CALL_NUM_PARAMS 2
#define DEACTIVATE_DATA_CALL_NO_REASON "0"

/* REQUEST_SETUP_DATA_CALL parameter values */
#define SETUP_DATA_CALL_PARAMS 7
#define CHAP_PAP_OK "3"
#define DATA_PROFILE_DEFAULT "0"
#define PROTO_IP "IP"
#define PROTO_IPV6 "IPV6"
#define PROTO_IPV4V6 "IPV4V6"

enum state {
	STATE_IDLE,
	STATE_ENABLING,
	STATE_DISABLING,
	STATE_ACTIVE,
};

struct gprs_context_data {
	GRil *ril;
	unsigned int active_ctx_cid;
	unsigned int active_rild_cid;
	enum state state;
};

static void ril_gprs_context_call_list_changed(struct ril_msg *message,
						gpointer user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct data_call *call = NULL;
	gboolean active_cid_found = FALSE;
	gboolean disconnect = FALSE;
	GSList *calls = NULL, *iterator = NULL;

	DBG("");

	if (message->req != RIL_UNSOL_DATA_CALL_LIST_CHANGED) {
		ofono_error("ril_gprs_update_calls: invalid message received %d",
				message->req);
		return;
	}

	calls = ril_util_parse_data_call_list(gcd->ril, message);

	DBG("number of call in call_list_changed is: %d", g_slist_length(calls));

	for (iterator = calls; iterator; iterator = iterator->next) {
		call = (struct data_call *) iterator->data;

		if (call->cid == gcd->active_rild_cid) {
			DBG("Found current call in call list: %d", call->cid);
			active_cid_found = TRUE;

			if (call->active == 0) {
				DBG("call->status is DISCONNECTED for cid: %d", call->cid);
				disconnect = TRUE;
				ofono_gprs_context_deactivated(gc, gcd->active_ctx_cid);
			}

			break;
		}
	}

	if (disconnect || active_cid_found == FALSE) {
		DBG("Clearing active context");

		gcd->active_ctx_cid = -1;
		gcd->active_rild_cid = -1;
		gcd->state = STATE_IDLE;
	}

	g_slist_foreach(calls, (GFunc) g_free, NULL);
	g_slist_free(calls);
}

static void ril_setup_data_call_cb(struct ril_msg *message, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct ofono_error error;
	struct parcel rilp;
	struct setup_data_call_reply reply;
	gboolean valid_reply = FALSE;
	char **split_ip_addr = NULL;

	if (message->error != RIL_E_SUCCESS) {
		DBG("Reply failure: %s", ril_error_to_string(message->error));
		decode_ril_error(&error, "FAIL");
		error.error = message->error;
		goto error;
	}

	/* TODO: Note, the parse_routines could take 'message'
	 * as a direct parameter instead of rilp.  This would
	 * simplify the calling routines even more, as the
	 * the ril_util_init_parcel() could move into the
	 * the parse* functions, as well as the g_ril_print_response
	 * calls...
	 */
	ril_util_init_parcel(message, &rilp);

	valid_reply = g_ril_parse_data_call_reply(gcd->ril,
							&reply,
							&rilp,
							&error);
	g_ril_print_response(gcd->ril, message);

	if (!valid_reply)
		goto error;

	if (reply.status != 0) {
		DBG("Reply failure; status %d", reply.status);
		gcd->state = STATE_IDLE;
		goto error;
	}

	/*
	 * TODO: consier moving this into parse_data_reply
	 *
	 * Note - the address may optionally include a prefix size
	 * ( Eg. "/30" ).  As this confuses NetworkManager, we
	 * explicitly strip any prefix after calculating the netmask.
	 */
	split_ip_addr = g_strsplit(reply.ip_addrs[0], "/", 2);
	if (split_ip_addr[0] == NULL) {
		DBG("Invalid IP address field returned: %s", reply.ip_addrs[0]);
		decode_ril_error(&error, "FAIL");
		goto error;
	}

	gcd->state = STATE_ACTIVE;
	gcd->active_rild_cid = reply.cid;

	ofono_gprs_context_set_interface(gc, reply.ifname);

	/* TODO:
	 * RILD can return multiple addresses; oFono only supports
	 * setting a single IPv4 address.  At this time, we only
	 * use the first address.  It's possible that a RIL may
	 * just specify the end-points of the point-to-point
	 * connection, in which case this code will need to
	 * changed to handle such a device.
	 */
	ofono_gprs_context_set_ipv4_netmask(gc,
			ril_util_get_netmask(reply.ip_addrs[0]));

	ofono_gprs_context_set_ipv4_address(gc, split_ip_addr[0], TRUE);
	ofono_gprs_context_set_ipv4_gateway(gc, reply.gateways[0]);

	ofono_gprs_context_set_ipv4_dns_servers(gc,
						(const char **) reply.dns_addresses);

	decode_ril_error(&error, "OK");

error:
	g_strfreev(reply.dns_addresses);
	g_strfreev(reply.ip_addrs);
	g_strfreev(reply.gateways);
	g_strfreev(split_ip_addr);

	g_free(reply.ifname);

	cb(&error, cbd->data);
}

static void ril_gprs_context_activate_primary(struct ofono_gprs_context *gc,
						const struct ofono_gprs_primary_context *ctx,
						ofono_gprs_context_cb_t cb, void *data)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct setup_data_call_req request_params;
	struct parcel rilp;
	struct ofono_error error;
	int request = RIL_REQUEST_SETUP_DATA_CALL;
	int ret;

	cbd->user = gc;
	gcd->active_ctx_cid = ctx->cid;
	gcd->state = STATE_ENABLING;

	parcel_init(&rilp);

	request_params.tech = RADIO_TECH_HSPA;
	request_params.data_profile = RIL_DATA_PROFILE_DEFAULT;
	request_params.apn = ctx->apn;
	request_params.username = ctx->username;
	request_params.password = ctx->password;
	request_params.auth_type = RIL_AUTH_BOTH;
	request_params.protocol = ctx->proto;

	if (g_ril_setup_data_call(gcd->ril, &request_params,
					&rilp, &error)) {
		ofono_error("Couldn't build SETUP_DATA_CALL request.");
		goto error;
	}

	ret = g_ril_send(gcd->ril,
				request,
				rilp.data,
				rilp.size,
				ril_setup_data_call_cb, cbd, g_free);

	/* NOTE - we could make the following function part of g_ril_send? */
	g_ril_print_request(gcd->ril, ret, request);

	parcel_free(&rilp);

error:
	if (ret <= 0) {
		ofono_error("Send RIL_REQUEST_SETUP_DATA_CALL failed.");

		g_free(cbd);
		CALLBACK_WITH_FAILURE(cb, data);
	}
}

static void ril_deactivate_data_call_cb(struct ril_msg *message, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct ofono_error error;

	DBG("");

	/* Reply has no data... */
	if (message->error == RIL_E_SUCCESS) {

		g_ril_print_response_no_args(gcd->ril, message);

		gcd->state = STATE_IDLE;
		CALLBACK_WITH_SUCCESS(cb, cbd->data);

	} else {
		DBG("Reply failure: %s", ril_error_to_string(message->error));

		decode_ril_error(&error, "FAIL");
		error.error = message->error;

		cb(&error, cbd->data);
	}
}

static void ril_gprs_context_deactivate_primary(struct ofono_gprs_context *gc,
						unsigned int id,
						ofono_gprs_context_cb_t cb, void *data)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct parcel rilp;
	gchar *cid = NULL;
	int request = RIL_REQUEST_DEACTIVATE_DATA_CALL;
	int ret;

	cbd->user = gc;

	gcd->state = STATE_DISABLING;

	parcel_init(&rilp);
	parcel_w_int32(&rilp, DEACTIVATE_DATA_CALL_NUM_PARAMS);

	cid = g_strdup_printf("%d", gcd->active_rild_cid);
	parcel_w_string(&rilp, cid);

	/*
	 * TODO: airplane-mode; change reason to '1',
	 * which means "radio power off".
	 */
	parcel_w_string(&rilp, DEACTIVATE_DATA_CALL_NO_REASON);

	ret = g_ril_send(gcd->ril,
				request,
				rilp.data,
				rilp.size,
				ril_deactivate_data_call_cb, cbd, g_free);

	g_ril_append_print_buf(gcd->ril, "(%s,0)", cid);
	g_ril_print_request(gcd->ril, ret, request);

	parcel_free(&rilp);
	g_free(cid);

	if (ret <= 0) {
		ofono_error("Send RIL_REQUEST_DEACTIVATE_DATA_CALL failed.");
		g_free(cbd);
		CALLBACK_WITH_FAILURE(cb, data);
	}
}

static void ril_gprs_context_detach_shutdown(struct ofono_gprs_context *gc,
					unsigned int id)
{
	DBG("");
}

static int ril_gprs_context_probe(struct ofono_gprs_context *gc,
					unsigned int vendor, void *data)
{
	GRil *ril = data;
	struct gprs_context_data *gcd;

	gcd = g_try_new0(struct gprs_context_data, 1);
	if (gcd == NULL)
		return -ENOMEM;

	gcd->ril = g_ril_clone(ril);
	gcd->active_ctx_cid = -1;
	gcd->active_rild_cid = -1;
	gcd->state = STATE_IDLE;

	ofono_gprs_context_set_data(gc, gcd);

	g_ril_register(gcd->ril, RIL_UNSOL_DATA_CALL_LIST_CHANGED,
			ril_gprs_context_call_list_changed, gc);
	return 0;
}

static void ril_gprs_context_remove(struct ofono_gprs_context *gc)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("");

	if (gcd->state != STATE_IDLE) {
		/* TODO: call detach_shutdown */
	}

	ofono_gprs_context_set_data(gc, NULL);

	g_ril_unref(gcd->ril);
	g_free(gcd);
}

static struct ofono_gprs_context_driver driver = {
	.name			= RILMODEM,
	.probe			= ril_gprs_context_probe,
	.remove			= ril_gprs_context_remove,
	.activate_primary       = ril_gprs_context_activate_primary,
	.deactivate_primary     = ril_gprs_context_deactivate_primary,
	.detach_shutdown        = ril_gprs_context_detach_shutdown,
};

void ril_gprs_context_init(void)
{
	ofono_gprs_context_driver_register(&driver);
}

void ril_gprs_context_exit(void)
{
	ofono_gprs_context_driver_unregister(&driver);
}
