/*
 *
 *  oFono - Open Source Telephony - RIL Modem Support
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *  Copyright (C) 2013 Canonical, Ltd. All rights reserved.
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
#include <ofono/sim.h>
#include "simutil.h"

#include "gril.h"
#include "grilutil.h"

#include "rilmodem.h"

/* Commands defined for TS 27.007 +CRSM */
#define CMD_READ_BINARY   176
#define CMD_READ_RECORD   178
#define CMD_GET_RESPONSE  192
#define CMD_UPDATE_BINARY 214
#define CMD_UPDATE_RECORD 220
#define CMD_STATUS        242
#define CMD_RETRIEVE_DATA 203
#define CMD_SET_DATA      219

struct sim_data {
	GRil *ril;
};

static void ril_file_info_cb(struct ril_msg *message, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_error error;
	ofono_sim_file_info_cb_t cb = cbd->cb;
	gboolean ok = FALSE;
	int sw1, sw2, flen, rlen, str;
	unsigned char *response;
	unsigned char access[3];
	unsigned char file_status;

	DBG("");

	if (message->error == RIL_E_SUCCESS) {
		decode_ril_error(&error, "OK");
	} else {
		DBG("Reply failure: %s", ril_error_to_string(message->error));
		decode_ril_error(&error, "FAIL");
		cb(&error, -1, -1, -1, NULL, EF_STATUS_INVALIDATED, cbd->data);
		return;
	}

	response = (guchar *) ril_util_parse_sim_io_rsp(message, &sw1, &sw2,
							&error);

	/* Based on atmodem SIM code. */
	if ((sw1 != 0x90 && sw1 != 0x91 && sw1 != 0x92 && sw1 != 0x9f) ||
			(sw1 == 0x90 && sw2 != 0x00)) {
		DBG("Error reply, invalid values: sw1: %02x sw2: %02x", sw1, sw2);
		memset(&error, 0, sizeof(error));

		error.type = OFONO_ERROR_TYPE_SIM;
		error.error = (sw1 << 8) | sw2;

		if (response)
			g_free(response);

		cb(&error, -1, -1, -1, NULL, EF_STATUS_INVALIDATED, cbd->data);
		return;
	}

	/* TODO: define constant for 0x62 */

	if (response) {
		if (response[0] == 0x62) {
			ok = sim_parse_3g_get_response(response, strlen((gchar *) response), &flen, &rlen,
							&str, access, NULL);

			file_status = EF_STATUS_VALID;
		} else
			ok = sim_parse_2g_get_response(response, strlen((gchar *) response), &flen, &rlen,
							&str, access, &file_status);

		g_free(response);
	}

	if (!ok)
		goto error;

	DBG("response OK; invoking cb - flen: %i, str: %i rlen: %i ", flen, str, rlen);
	cb(&error, flen, str, rlen, access, file_status, cbd->data);
	return;

error:
	DBG("response !OK; %s: ", response);
	CALLBACK_WITH_FAILURE(cb, -1, -1, -1, NULL,
				EF_STATUS_INVALIDATED, cbd->data);
}

static void ril_sim_read_info(struct ofono_sim *sim, int fileid,
				const unsigned char *path, unsigned int path_len,
				ofono_sim_file_info_cb_t cb,
				void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct parcel rilp;
	int ret;

	DBG("fileid: %s", sim_fileid_to_string(fileid));

	/*
	 * snprintf(buf, sizeof(buf), "AT+CRSM=192,%i", fileid);
	 *
	 * AT+CRSM=192,%i  == Restricted SIM Access::GET RESPONSE
	 * AT+CSIM         == Generic SIM access
	 */

	parcel_init(&rilp);
	parcel_w_int32(&rilp, CMD_GET_RESPONSE);
	parcel_w_int32(&rilp, fileid);

	/* pathid */
	parcel_w_string(&rilp, (char *) path);

	parcel_w_int32(&rilp, 0);   /* P1 */
	parcel_w_int32(&rilp, 0);   /* P2 */
	parcel_w_int32(&rilp, 255); /* P3 - max length */

	/* send REQUEST to RIL */
	ret = g_ril_send(sd->ril,
				RIL_REQUEST_SIM_IO,
				rilp.data,
				rilp.size,
				ril_file_info_cb, cbd, g_free);

	parcel_free(&rilp);

	if (ret <= 0) {
		g_free(cbd);
		CALLBACK_WITH_FAILURE(cb, -1, -1, -1, NULL,
				EF_STATUS_INVALIDATED, data);
	}
}

static void ril_file_io_cb(struct ril_msg *message, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_error error;
	ofono_sim_read_cb_t cb = cbd->cb;
	int sw1, sw2;
	unsigned char *response;

	DBG("");

	if (message->error == RIL_E_SUCCESS) {
		decode_ril_error(&error, "OK");
	} else {
		DBG("Reply failure: %s", ril_error_to_string(message->error));

		/* TODO: can extra data be included in &error? */
		decode_ril_error(&error, "FAIL");
		cb(&error, NULL, 0, cbd->data);
		return;
	}

	response = (guchar *) ril_util_parse_sim_io_rsp(message, &sw1, &sw2,
							&error);

	if (response == NULL) {
		DBG("Error parsing IO response");
		decode_ril_error(&error, "FAIL");
		cb(&error, NULL, 0, cbd->data);
		return;
	}

	cb(&error, response, strlen((gchar *) response), cbd->data);
	g_free(response);
}

static void ril_sim_read_binary(struct ofono_sim *sim, int fileid,
				int start, int length,
				const unsigned char *path, unsigned int path_len,
				ofono_sim_read_cb_t cb, void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct parcel rilp;
	int ret;

	DBG("fileid: %s", sim_fileid_to_string(fileid));

	/* snprintf(buf, sizeof(buf), "AT+CRSM=176,%i,%i,%i,%i", fileid,
	   start >> 8, start & 0xff, length); */

	parcel_init(&rilp);
	parcel_w_int32(&rilp, CMD_READ_BINARY);
	parcel_w_int32(&rilp, fileid);

	/* pathid */
	parcel_w_string(&rilp, (char *) path);

	parcel_w_int32(&rilp, (start >> 8));   /* P1 */
	parcel_w_int32(&rilp, (start & 0xff));   /* P2 */
	parcel_w_int32(&rilp, length); /* P3 - max length */

	ret = g_ril_send(sd->ril,
				RIL_REQUEST_SIM_IO,
				rilp.data,
				rilp.size,
				ril_file_io_cb, cbd, g_free);
	parcel_free(&rilp);

	if (ret <= 0) {
		g_free(cbd);
		CALLBACK_WITH_FAILURE(cb, NULL, 0, data);
	}
}

static void ril_sim_read_record(struct ofono_sim *sim, int fileid,
				int record, int length,
				const unsigned char *path, unsigned int path_len,
				ofono_sim_read_cb_t cb, void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct parcel rilp;
	int ret;

	DBG("fileid: %s", sim_fileid_to_string(fileid));
        /* snprintf(buf, sizeof(buf), "AT+CRSM=178,%i,%i,4,%i", fileid,
	   record, length); */

	parcel_init(&rilp);
	parcel_w_int32(&rilp, CMD_READ_RECORD);
	parcel_w_int32(&rilp, fileid);

	/* pathid */
	parcel_w_string(&rilp, (char *) path);

	parcel_w_int32(&rilp, record);   /* P1 */
	parcel_w_int32(&rilp, 4);   /* P2 */
	parcel_w_int32(&rilp, length); /* P3 - max length */

	ret = g_ril_send(sd->ril,
				RIL_REQUEST_SIM_IO,
				rilp.data,
				rilp.size,
				ril_file_io_cb, cbd, g_free);

	parcel_free(&rilp);

	if (ret <= 0) {
		g_free(cbd);
		CALLBACK_WITH_FAILURE(cb, NULL, 0, data);
	}
}

static void ril_imsi_cb(struct ril_msg *message, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sim_imsi_cb_t cb = cbd->cb;
	struct ofono_error error;
	struct parcel rilp;
	gchar *imsi;

	if (message->error == RIL_E_SUCCESS) {
		DBG("GET IMSI reply - OK");
		decode_ril_error(&error, "OK");
	} else {
		DBG("Reply failure: %s", ril_error_to_string(message->error));
		decode_ril_error(&error, "FAIL");
		cb(&error, NULL, cbd->data);
		return;
	}

	/* Set up Parcel struct for proper parsing */
	rilp.data = message->buf;
	rilp.size = message->buf_len;
	rilp.capacity = message->buf_len;
	rilp.offset = 0;

        /* 15 is the max length of IMSI
	 * add 4 bytes for string length */
        /* FIXME: g_assert(message->buf_len <= 19); */

	imsi = parcel_r_string(&rilp);

	DBG("ril_imsi_cb: IMSI: %s", imsi);

	cb(&error, imsi, cbd->data);
	g_free(imsi);
}

static void ril_read_imsi(struct ofono_sim *sim, ofono_sim_imsi_cb_t cb,
				void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct parcel rilp;
	int ret;

	DBG("");

	parcel_init(&rilp);
	parcel_w_string(&rilp, NULL);

	ret = g_ril_send(sd->ril, RIL_REQUEST_GET_IMSI,
				rilp.data, rilp.size, ril_imsi_cb, cbd, g_free);
	parcel_free(&rilp);

	if (ret <= 0) {
		DBG("g_ril_send failed...");
		g_free(cbd);
		CALLBACK_WITH_FAILURE(cb, NULL, data);
	}
}

static gboolean ril_sim_register(gpointer user)
{
	struct ofono_sim *sim = user;

	DBG("");

	ofono_sim_register(sim);

	return FALSE;
}

static int ril_sim_probe(struct ofono_sim *sim, unsigned int vendor,
				void *data)
{
	GRil *ril = data;
	struct sim_data *sd;

	DBG("");

	sd = g_new0(struct sim_data, 1);
	sd->ril = g_ril_clone(ril);

	ofono_sim_set_data(sim, sd);

        /*
	 * TODO: analyze if capability check is needed
	 * and/or timer should be adjusted.
	 *
	 * ofono_sim_register() needs to be called after the
	 * driver has been set in ofono_sim_create(), which
	 * calls this function.  Most other drivers make some
	 * kind of capabilities query to the modem, and then
	 * call register in the callback; we use an idle event
	 * instead.
	 */
	g_idle_add(ril_sim_register, sim);

	return 0;
}

static void ril_sim_remove(struct ofono_sim *sim)
{
	struct sim_data *sd = ofono_sim_get_data(sim);

	ofono_sim_set_data(sim, NULL);

	g_ril_unref(sd->ril);
	g_free(sd);
}

static struct ofono_sim_driver driver = {
	.name			= "rilmodem",
	.probe                  = ril_sim_probe,
	.remove                 = ril_sim_remove,
	.read_file_info		= ril_sim_read_info,
	.read_file_transparent	= ril_sim_read_binary,
	.read_file_linear	= ril_sim_read_record,
	.read_file_cyclic	= ril_sim_read_record,
/*	.write_file_transparent	= ril_sim_update_binary,
 *	.write_file_linear	= ril_sim_update_record,
 *	.write_file_cyclic	= ril_sim_update_cyclic,
 */
 	.read_imsi		= ril_read_imsi,
/*	.query_passwd_state	= at_pin_query,
 *	.query_pin_retries	= at_pin_retries_query,
 *	.send_passwd		= at_pin_send,
 *	.reset_passwd		= at_pin_send_puk,
 *	.lock			= at_pin_enable,
 *	.change_passwd		= at_change_passwd,
 *	.query_locked		= at_pin_query_enabled,
 */
};

void ril_sim_init(void)
{
	DBG("");
	ofono_sim_driver_register(&driver);
}

void ril_sim_exit(void)
{
	ofono_sim_driver_unregister(&driver);
}
