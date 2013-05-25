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
#include "grilutil.h"

#include "rilmodem.h"

/* TODO: create a table lookup*/
#define PREFIX_30_NETMASK "255.255.255.252"
#define PREFIX_29_NETMASK "255.255.255.248"
#define PREFIX_28_NETMASK "255.255.255.240"
#define PREFIX_27_NETMASK "255.255.255.224"
#define PREFIX_26_NETMASK "255.255.255.192"
#define PREFIX_25_NETMASK "255.255.255.128"
#define PREFIX_24_NETMASK "255.255.255.0"

#define SETUP_DATA_CALL_PARAMS 7

/* REQUEST_SETUP_DATA_CALL parameter values */
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
	unsigned int active_context;
	unsigned int rild_context;
	char username[OFONO_GPRS_MAX_USERNAME_LENGTH + 1];
	char password[OFONO_GPRS_MAX_PASSWORD_LENGTH + 1];
	enum state state;
	unsigned int vendor;
};

/* TODO: make conditional */
static char printBuf[PRINTBUF_SIZE];

static char *ril_gprs_context_get_prefix(const char *address)
{
	char *result = "255.255.255.255";

	if (g_str_has_suffix(address, "/30")) {
		result = PREFIX_30_NETMASK;
	} else if (g_str_has_suffix(address, "/29")) {
		result = PREFIX_29_NETMASK;
	} else if (g_str_has_suffix(address, "/28")) {
		result = PREFIX_28_NETMASK;
	} else if (g_str_has_suffix(address, "/27")) {
		result = PREFIX_27_NETMASK;
	} else if (g_str_has_suffix(address, "/26")) {
		result = PREFIX_26_NETMASK;
	} else if (g_str_has_suffix(address, "/25")) {
		result = PREFIX_25_NETMASK;
	} else if (g_str_has_suffix(address, "/24")) {
		result = PREFIX_24_NETMASK;
	}

	DBG("address: %s netmask: %s", address, result);

	return result;
}
static void ril_setup_data_call_cb(struct ril_msg *message, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct ofono_error error;
	struct parcel rilp;
	gchar **dns_addresses = NULL;
	int status, retry_time, cid, active, num, version;
	char *type, *ifname, *addresses, *dnses, *gateways;

	/* TODO:
	 * Cleanup duplicate code between this function and
	 * ril_util_parse_data_call_list().
	 */

	/* valid size: 36 (34 if HCRADIO defined) */
	if (message->buf_len < 36) {
		DBG("Parcel is less then minimum DataCallResponseV6 size!");
		goto error;
	}

	if (message->error != RIL_E_SUCCESS) {
		DBG("Reply failure: %s", ril_error_to_string(message->error));
		decode_ril_error(&error, "FAIL");
		error.error = message->error;
		goto error;
	}

	/* TODO: make conditional */
	appendPrintBuf("[%04d]< %s",
			message->serial_no,
			ril_request_id_to_string(message->req));
	startResponse;
	/* TODO: make conditional */

	ril_util_init_parcel(message, &rilp);

	/* RIL version */
	version = parcel_r_int32(&rilp);

	/* Size of call list */
	/* TODO: What if there's more than 1 call in the list?? */
	num = parcel_r_int32(&rilp);

	status = parcel_r_int32(&rilp);
	retry_time = parcel_r_int32(&rilp);
	cid = parcel_r_int32(&rilp);
	active = parcel_r_int32(&rilp);

	type = parcel_r_string(&rilp);
	ifname = parcel_r_string(&rilp);
	addresses = parcel_r_string(&rilp);
	dnses = parcel_r_string(&rilp);
	gateways = parcel_r_string(&rilp);

	/* TODO: make conditional */
	appendPrintBuf("%sversion=%d,num=%d",
			printBuf,
			version,
			num);

	appendPrintBuf("%s [status=%d,retry=%d,cid=%d,active=%d\
                      type=%s,ifname=%s,address=%s,dns=%s,gateways=%s]",
			printBuf,
			status,
			retry_time,
			cid,
			active,
			type,
			ifname,
			addresses,
			dnses,
			gateways);
	closeResponse;
	printResponse;
	/* TODO: make conditional */

	if (status != 0) {
		DBG("Reply failure; status %d", status);
		gcd->state = STATE_IDLE;
		goto error;
	}

	gcd->state = STATE_ACTIVE;
	gcd->rild_context = cid;

	ofono_gprs_context_set_interface(gc, ifname);

	/* TODO:
	 * RILD can return multiple addresses; oFono only supports
	 * setting a single IPv4 address.  Add code to split and
	 * only use the first address.
	 *
	 * Note - the address may optionally include a prefix size
	 * ( Eg. "/30" ).
	 */
	ofono_gprs_context_set_ipv4_address(gc, addresses, TRUE);

	ofono_gprs_context_set_ipv4_netmask(gc,
			ril_gprs_context_get_prefix(addresses));

	/* TODO:
	 * RILD can return multiple addresses; oFono only supports
	 * setting a single IPv4 gateway.  Add code to split and
	 * only use the first address.
	 */
	ofono_gprs_context_set_ipv4_gateway(gc, gateways);

	/* Split DNS addresses */
	dns_addresses = g_strsplit(dnses, " ", 3);
	ofono_gprs_context_set_ipv4_dns_servers(gc,
						(const char **) dns_addresses);
	g_strfreev(dns_addresses);

	g_free(type);
	g_free(ifname);
	g_free(addresses);
	g_free(dnses);
	g_free(gateways);

	CALLBACK_WITH_SUCCESS(cb, cbd->data);
	return;

error:
	cb(&error, cbd->data);
}

static void ril_gprs_context_activate_primary(struct ofono_gprs_context *gc,
						const struct ofono_gprs_primary_context *ctx,
						ofono_gprs_context_cb_t cb, void *data)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct parcel rilp;
	guchar profile[5] = { 0x00 };
	gchar *protocol = PROTO_IP;
	gchar *tech[3];
	int request = RIL_REQUEST_SETUP_DATA_CALL;
	int ret;

        /* TODO: make conditional */
	clearPrintBuf;
	startRequest;
        /* TODO: make conditional */

	cbd->user = gc;
	gcd->active_context = ctx->cid;
	gcd->state = STATE_ENABLING;

	memcpy(gcd->username, ctx->username, sizeof(ctx->username));
	memcpy(gcd->password, ctx->password, sizeof(ctx->password));

	parcel_init(&rilp);
	parcel_w_int32(&rilp, SETUP_DATA_CALL_PARAMS);

        /* RadioTech: hardcoded to HSPA for now... */
	sprintf(tech, "%d", (int) RADIO_TECH_HSPA);
	parcel_w_string(&rilp, (char *) tech);

        /*
	 * TODO ( OEM/Tethering ): DataProfile:
	 *
	 * Other options are TETHERING (1) or OEM_BASE (1000).
	 */
	parcel_w_string(&rilp, DATA_PROFILE_DEFAULT);

	/* APN */
	parcel_w_string(&rilp, (char *) (ctx->apn));

	if (ctx->username && strlen(ctx->username)) {
		parcel_w_string(&rilp, (char *) (ctx->username));
	} else {
		parcel_w_string(&rilp, NULL);
	}

	if (ctx->password && strlen(ctx->password)) {
		parcel_w_string(&rilp, (char *) (ctx->password));
	} else {
		parcel_w_string(&rilp, NULL);
	}

	/*
	 * TODO: review with operators...
         * Auth type: PAP/CHAP may be performed
	 */
	parcel_w_string(&rilp, CHAP_PAP_OK);

	switch (ctx->proto) {
	case OFONO_GPRS_PROTO_IPV6:
		protocol = PROTO_IPV6;
		break;
	case OFONO_GPRS_PROTO_IPV4V6:
		protocol = PROTO_IPV4V6;
		break;
	case OFONO_GPRS_PROTO_IP:
		break;
	default:
		DBG("Invalid protocol");
	}

	parcel_w_string(&rilp, protocol);

	appendPrintBuf("%s %s,%s,%s,%s,%s,%s,%s",
			printBuf,
			tech,
			DATA_PROFILE_DEFAULT,
			ctx->apn,
			ctx->username,
			ctx->password,
			CHAP_PAP_OK,
			protocol);

	ret = g_ril_send(gcd->ril,
				request,
				rilp.data,
				rilp.size,
				ril_setup_data_call_cb, cbd, g_free);

	/* TODO: make conditional */
	closeRequest;
	printRequest(ret, request);
	/* TODO: make conditional */

	parcel_free(&rilp);
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

	/* Reply has no data... */

	if (message->error == RIL_E_SUCCESS) {
		appendPrintBuf("[%04d]< %s",
				message->serial_no,
				ril_request_id_to_string(message->req));

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
	int request = RIL_REQUEST_DEACTIVATE_DATA_CALL;
	int ret;

	cbd->user = gc;

	gcd->state = STATE_DISABLING;

	parcel_init(&rilp);
	parcel_w_int32(&rilp, gcd->rild_context);

	/*
	 * TODO: airplane-mode; change reason to '1',
	 * which means "radio power off".
	 */
	parcel_w_int32(&rilp, 0);

	ret = g_ril_send(gcd->ril,
				request,
				rilp.data,
				rilp.size,
				ril_deactivate_data_call_cb, cbd, g_free);

	/* TODO: make conditional */
	clearPrintBuf;
	printRequest(ret, request);
	/* TODO: make conditional */

	parcel_free(&rilp);
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
	struct stat st;

	DBG("");

	gcd = g_try_new0(struct gprs_context_data, 1);
	if (gcd == NULL)
		return -ENOMEM;

	gcd->ril = g_ril_clone(ril);
	gcd->vendor = vendor;

	ofono_gprs_context_set_data(gc, gcd);

	/* TODO: Register for disconnects! */
        /* g_at_chat_register(chat, "+CGEV:", cgev_notify, FALSE, gc, NULL); */

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
	.name			= "rilmodem",
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
