/*
 *
 *  oFono - Open Source Telephony
 *
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

#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <glib.h>
#include <errno.h>

#include <ofono/modem.h>
#include <ofono/gprs-context.h>
#include <ofono/types.h>

#include "gril.h"
#include "grilunsol.h"

/*
 * TODO: It may make sense to split this file into
 * domain-specific files ( eg. test-grilrequest-gprs-context.c )
 * once more tests are added.
 */

static const struct ril_msg unsol_data_call_list_changed_invalid_1 = {
	.buf = "",
	.buf_len = 0,
	.unsolicited = TRUE,
	.req = RIL_UNSOL_DATA_CALL_LIST_CHANGED,
	.serial_no = 0,
	.error = 0,
};

/*
 * The following hexadecimal data represents a serialized Binder parcel
 * instance containing a valid RIL_UNSOL_DATA_CALL_LIST_CHANGED message
 * with the following parameters:
 *
 * (version=7,num=1 [status=0,retry=-1,cid=0,active=1,type=IP,
 * ifname=rmnet_usb0,address=10.209.114.102/30,
 * dns=172.16.145.103 172.16.145.103,gateways=10.209.114.101]}
 */
static const guchar unsol_data_call_list_changed_parcel1[216] = {
	0x00, 0x00, 0x00, 0xd4, 0x01, 0x00, 0x00, 0x00, 0xf2, 0x03, 0x00, 0x00,
	0x07, 0x00, 0x00, 0x00,	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,	0x01, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x49, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0a, 0x00, 0x00, 0x00, 0x72, 0x00, 0x6d, 0x00, 0x6e, 0x00, 0x65, 0x00,
	0x74, 0x00, 0x5f, 0x00,	0x75, 0x00, 0x73, 0x00, 0x62, 0x00, 0x30, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,	0x31, 0x00, 0x30, 0x00,
	0x2e, 0x00, 0x32, 0x00, 0x30, 0x00, 0x39, 0x00, 0x2e, 0x00, 0x31, 0x00,
	0x31, 0x00, 0x34, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x30, 0x00, 0x32, 0x00,
	0x2f, 0x00, 0x33, 0x00,	0x30, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00,
	0x31, 0x00, 0x37, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x36, 0x00,
	0x2e, 0x00, 0x31, 0x00, 0x34, 0x00, 0x35, 0x00, 0x2e, 0x00, 0x31, 0x00,
	0x30, 0x00, 0x33, 0x00, 0x20, 0x00, 0x31, 0x00, 0x37, 0x00, 0x32, 0x00,
	0x2e, 0x00, 0x31, 0x00,	0x36, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x34, 0x00,
	0x35, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x30, 0x00,	0x33, 0x00, 0x00, 0x00,
	0x0e, 0x00, 0x00, 0x00, 0x31, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x32, 0x00,
	0x30, 0x00, 0x39, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x31, 0x00, 0x34, 0x00,
	0x2e, 0x00, 0x31, 0x00,	0x30, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const struct ril_msg unsol_data_call_list_changed_valid_1 = {
	.buf = (gchar *) &unsol_data_call_list_changed_parcel1,
	.buf_len = 216,
	.unsolicited = TRUE,
	.req = RIL_UNSOL_DATA_CALL_LIST_CHANGED,
	.serial_no = 0,
	.error = 0,
};

static void test_unsol_data_call_list_changed_invalid(gconstpointer data)
{
	/* TODO: fix de-const cast... */
	const struct ril_msg *message = (struct ril_msg *) data;
	struct ofono_error error;
	struct unsol_data_call_list *unsol;

        unsol = g_ril_unsol_parse_data_call_list(NULL, message, &error);
	g_assert(unsol != NULL);
	g_ril_unsol_free_data_call_list(unsol);

	g_assert(error.type == OFONO_ERROR_TYPE_FAILURE &&
			error.error == -EINVAL);
}

static void test_unsol_data_call_list_changed_valid(gconstpointer data)
{
	/* TODO: fix de-const cast... */
	const struct ril_msg *message = (struct ril_msg *) data;
	struct ofono_error error;
	struct unsol_data_call_list *unsol;

        unsol = g_ril_unsol_parse_data_call_list(NULL, message, &error);
	g_assert(unsol != NULL);
	g_ril_unsol_free_data_call_list(unsol);

	g_assert(error.type == OFONO_ERROR_TYPE_NO_ERROR &&
			error.error == 0);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_data_func("/testgrilrequest/gprs-context: "
				"invalid DATA_CALL_LIST_CHANGED Test 1",
				&unsol_data_call_list_changed_invalid_1,
				test_unsol_data_call_list_changed_invalid);

	g_test_add_data_func("/testgrilrequest/gprs-context: "
				"valid DATA_CALL_LIST_CHANGED Test 1",
				&unsol_data_call_list_changed_valid_1,
				test_unsol_data_call_list_changed_valid);

	return g_test_run();
}
