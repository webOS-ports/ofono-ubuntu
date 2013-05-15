/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *  Copyright (C) 2010  ST-Ericsson AB.
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

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/gprs.h>
#include <ofono/types.h>

#include "gril.h"
#include "grilutil.h"
#include "common.h"
#include "rilmodem.h"

struct gprs_data {
	GRil *ril;
	unsigned int vendor;
	int max_cids;
	int tech;
};

static void ril_gprs_set_attached(struct ofono_gprs *gprs, int attached,
					ofono_gprs_cb_t cb, void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	struct ofono_error error;

	DBG("");

	decode_ril_error(&error, "OK");

	/* This code should just call the callback with OK, and be done
	 * there's no explicit RIL command to cause an attach.
	 *
	 * The core gprs code calls driver->set_attached() when a netreg
	 * notificaiton is received and any configured roaming conditions
	 * are met.
	 */

	cb(&error, cbd->data);
	g_free(cbd);
}

static void ril_data_reg_cb(struct ril_msg *message, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_status_cb_t cb = cbd->cb;
	struct ofono_gprs *gprs = cbd->user;
	struct gprs_data *gd = ofono_gprs_get_data(gprs);
	struct ofono_error error;
	int status, lac, ci, tech;
	int max_cids = 1;

	if (message->error == RIL_E_SUCCESS) {
		DBG("DATA_REGISTRATION reply - OK");
		decode_ril_error(&error, "OK");
	} else {
		ofono_error("Reply failure: %s", ril_error_to_string(message->error));
		decode_ril_error(&error, "FAIL");

		if (cb)
			cb(&error, -1, cbd->data);
		return;
	}

	if (ril_util_parse_reg(message, &status,
				&lac, &ci, &tech, &max_cids) == FALSE) {
		ofono_error("Failure parsing data registration response.");
		if (cb)
			CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	DBG("oFono reg - status: %s, lac: %x, ci: %x, tech: %s max_cids: %d",
		registration_status_to_string(status),
		lac, ci, registration_tech_to_string(tech),
		max_cids);

	if (gd->max_cids == 0 && cb == NULL) {
		DBG("Setting max cids to %d", max_cids);
		gd->max_cids = max_cids;
		gd->tech = tech;
		ofono_gprs_set_cid_range(gprs, 1, max_cids);

		/* Register listeners for:
		 * - detach_notify()
		 * - status_notify()
		 * - suspend/resume_notify() - hw optional
		 * - bearer_notify
		 */
		ofono_gprs_register(gprs);
		return;
	}

	cb(&error, status, cbd->data);
}

static void ril_gprs_registration_status(struct ofono_gprs *gprs,
					ofono_gprs_status_cb_t cb,
					void *data)
{
	struct gprs_data *gd = ofono_gprs_get_data(gprs);
	struct cb_data *cbd = cb_data_new(cb, data);
	cbd->user = gprs;

	DBG("");

	if (g_ril_send(gd->ril, RIL_REQUEST_DATA_REGISTRATION_STATE,
			NULL, 0, ril_data_reg_cb, cbd, g_free) <= 0) {
		ofono_error("Send RIL_REQUEST_DATA_RESTISTRATION_STATE failed.");

		g_free(cbd);
		CALLBACK_WITH_FAILURE(cb, -1, data);
	}
}

static int ril_gprs_probe(struct ofono_gprs *gprs,
				unsigned int vendor, void *data)
{
	GRil *ril = data;
	struct gprs_data *gd;

        DBG("");

	gd = g_try_new0(struct gprs_data, 1);
	if (gd == NULL)
		return -ENOMEM;

	gd->ril = g_ril_clone(ril);
	gd->vendor = vendor;

	ofono_gprs_set_data(gprs, gd);

	ril_gprs_registration_status(gprs, NULL, NULL);

	return 0;
}

static void ril_gprs_remove(struct ofono_gprs *gprs)
{
	struct gprs_data *gd = ofono_gprs_get_data(gprs);

	DBG("");

	ofono_gprs_set_data(gprs, NULL);

	g_ril_unref(gd->ril);
	g_free(gd);
}

static struct ofono_gprs_driver driver = {
	.name			= "rilmodem",
	.probe			= ril_gprs_probe,
	.remove			= ril_gprs_remove,
	.set_attached		= ril_gprs_set_attached,
	.attached_status	= ril_gprs_registration_status,
};

void ril_gprs_init(void)
{
	ofono_gprs_driver_register(&driver);
}

void ril_gprs_exit(void)
{
	ofono_gprs_driver_unregister(&driver);
}
