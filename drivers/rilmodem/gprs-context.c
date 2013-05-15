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

#define TUN_SYSFS_DIR "/sys/devices/virtual/misc/tun"

#define STATIC_IP_NETMASK "255.255.255.255"


#define SETUP_DATA_CALL_PARAMS 8

/* REQUEST_SETUP_DATA_CALL parameter values */
#define DEFAULT_TETHERING_PROFILE "0"
#define GSM_UMTS_TECH "1"
#define CHAP_PAP_OK "3"

enum state {
	STATE_IDLE,
	STATE_ENABLING,
	STATE_DISABLING,
	STATE_ACTIVE,
};

struct gprs_context_data {
	GRil *ril;
	unsigned int active_context;
	char username[OFONO_GPRS_MAX_USERNAME_LENGTH + 1];
	char password[OFONO_GPRS_MAX_PASSWORD_LENGTH + 1];
        /* GAtPPP *ppp; */
	enum state state;
	ofono_gprs_context_cb_t cb;
	void *cb_data;                                  /* Callback data */
	unsigned int vendor;
};


static void ril_setup_data_call_cb(struct ril_msg *message, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct parcel rilp;

	DBG("");
	ril_util_init_parcel(message, &rilp);

	/* */
}

static void ril_gprs_context_activate_primary(struct ofono_gprs_context *gc,
						const struct ofono_gprs_primary_context *ctx,
						ofono_gprs_context_cb_t cb, void *data)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct parcel rilp;
	gchar protocol[1];

	DBG("");

	parcel_init(&rilp);
	parcel_w_int32(&rilp, SETUP_DATA_CALL_PARAMS);
	parcel_w_string(&rilp, GSM_UMTS_TECH);  /* RadioTech: hardcoded to GSM/UMTS for now... */

        /* DataProfile:
	 *
	 * set to default value (0).  Other possibilities
	 * are 1 (tethering), and 1000 (OEM base).
	 *
	 * TODO: tethering support, this may need to change.
	 * */
	parcel_w_string(&rilp, DEFAULT_TETHERING_PROFILE);

	/* APN */
	parcel_w_string(&rilp, ((struct ofono_gprs_primary_context *) ctx)->apn);

	if (strlen(ctx->username)) {
		parcel_w_string(&rilp,
				((struct ofono_gprs_primary_context *) ctx)->username);
	} else {
		parcel_w_string(&rilp, NULL);
	}

	if (strlen(ctx->password)) {
		parcel_w_string(&rilp,
				((struct ofono_gprs_primary_context *) ctx)->password);
	} else {
		parcel_w_string(&rilp, NULL);
	}

	/* TODO: review with operators... */
	parcel_w_string(&rilp, CHAP_PAP_OK); /* Auth type: PAP/CHAP may be performed */

	/* FIXME: review this... */
	sprintf(protocol, "%d", ctx->proto);
	parcel_w_string(&rilp, protocol);

	if (g_ril_send(gcd->ril, RIL_REQUEST_SETUP_DATA_CALL,
			NULL, 0, ril_setup_data_call_cb, cbd, g_free) <= 0) {
		ofono_error("Send RIL_REQUEST_SETUP_DATA_CALL failed.");

		g_free(cbd);
		CALLBACK_WITH_FAILURE(cb, data);
	}

	parcel_free(&rilp);
}

static void ril_gprs_context_deactivate_primary(struct ofono_gprs_context *gc,
						unsigned int id,
						ofono_gprs_context_cb_t cb, void *data)
{
	DBG("");
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

	if (stat(TUN_SYSFS_DIR, &st) < 0) {
		ofono_error("Missing support for TUN/TAP devices");
		return -ENODEV;
	}

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


	/*
	 * if (gcd->state != STATE_IDLE && gcd->ppp) {
	 *	g_at_ppp_unref(gcd->ppp);
	 *	g_at_chat_resume(gcd->chat);
	 *}
	 */

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
