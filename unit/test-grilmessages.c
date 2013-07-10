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

#include <ofono/gprs-context.h>
#include <ofono/types.h>

#include "gril.h"
#include "grilmessages.h"

static void test_invalid_setup_data_calls(void)
{
	gboolean result;
	struct setup_data_call_req request;
	struct parcel rilp;
	struct ofono_error error;

	/* No parcel_init necessary, as these tests
	 * all fail validity checks.
	 */

	/* Test invalid radio tech values */
	request.tech = RADIO_TECH_UNKNOWN;
	result = g_ril_setup_data_call(NULL, &request, &rilp, &error);
	g_assert(result == FALSE);
	g_assert(error.type == OFONO_ERROR_TYPE_FAILURE &&
			error.error == -EINVAL);

	request.tech = 2112;
	result = g_ril_setup_data_call(NULL, &request, &rilp, &error);
	g_assert(result == FALSE);
	g_assert(error.type == OFONO_ERROR_TYPE_FAILURE &&
			error.error == -EINVAL);

	/* Test invalid data profile */
	request.tech = RADIO_TECH_GPRS;
	request.data_profile = 5;
	result = g_ril_setup_data_call(NULL, &request, &rilp, &error);
	g_assert(result == FALSE);
	g_assert(error.type == OFONO_ERROR_TYPE_FAILURE &&
			error.error == -EINVAL);

	/* Invalid APNs */
	request.tech = RADIO_TECH_GPRS;
	request.data_profile = RIL_DATA_PROFILE_DEFAULT;
	request.apn = NULL;
	result = g_ril_setup_data_call(NULL, &request, &rilp, &error);
	g_assert(result == FALSE);
	g_assert(error.type == OFONO_ERROR_TYPE_FAILURE &&
			error.error == -EINVAL);

	/* zero length */
	request.tech = RADIO_TECH_GPRS;
	request.data_profile = RIL_DATA_PROFILE_DEFAULT;
	request.apn = "";
	result = g_ril_setup_data_call(NULL, &request, &rilp, &error);
	g_assert(result == FALSE);
	g_assert(error.type == OFONO_ERROR_TYPE_FAILURE &&
			error.error == -EINVAL);

	/* greater than max length */
	request.tech = RADIO_TECH_GPRS;
	request.data_profile = RIL_DATA_PROFILE_DEFAULT;
	request.apn = "12345678901234567890123456789012345678901234567890"
		"123456789012345678901234567890123456789012345678901";

	result = g_ril_setup_data_call(NULL, &request, &rilp, &error);
	g_assert(result == FALSE);
	g_assert(error.type == OFONO_ERROR_TYPE_FAILURE && error.error == -EINVAL);

	/* Invalid auth type */
	request.tech = RADIO_TECH_GPRS;
	request.data_profile = RIL_DATA_PROFILE_DEFAULT;
	request.apn = "test.apn";
	request.auth_type = 4;
	result = g_ril_setup_data_call(NULL, &request, &rilp, &error);
	g_assert(result == FALSE);
	g_assert(error.type == OFONO_ERROR_TYPE_FAILURE && error.error == -EINVAL);

	/* Invalid protocol */
	request.tech = RADIO_TECH_GPRS;
	request.data_profile = RIL_DATA_PROFILE_DEFAULT;
	request.apn = "test.apn";
	request.auth_type = RIL_AUTH_BOTH;
	request.protocol = 3;
	result = g_ril_setup_data_call(NULL, &request, &rilp, &error);
	g_assert(result == FALSE);
	g_assert(error.type == OFONO_ERROR_TYPE_FAILURE && error.error == -EINVAL);
}

static void test_valid_setup_data_calls(void)
{
	gboolean result;
	struct setup_data_call_req request;
	struct parcel rilp;
	struct ofono_error error;

	/* Valid request #1 */
	parcel_init(&rilp);
	request.tech = RADIO_TECH_GPRS;
	request.data_profile = RIL_DATA_PROFILE_DEFAULT;
	request.apn = "test.apn";
	request.username = NULL;
	request.password = NULL;
	request.auth_type = RIL_AUTH_BOTH;
	request.protocol = OFONO_GPRS_PROTO_IP;
	result = g_ril_setup_data_call(NULL, &request, &rilp, &error);
	g_assert(result == TRUE);
	g_assert(error.type == OFONO_ERROR_TYPE_NO_ERROR &&
			error.error == 0);
	parcel_free(&rilp);

	/* valid request #2 */
	parcel_init(&rilp);
	request.tech = RADIO_TECH_GPRS;
	request.data_profile = RIL_DATA_PROFILE_DEFAULT;
	request.apn = "test.apn";
	request.username = "";
	request.password = "";
	request.auth_type = RIL_AUTH_BOTH;
	request.protocol = OFONO_GPRS_PROTO_IP;
	result = g_ril_setup_data_call(NULL, &request, &rilp, &error);
	g_assert(result == TRUE);
	g_assert(error.type == OFONO_ERROR_TYPE_NO_ERROR &&
			error.error == 0);
	parcel_free(&rilp);

	/* valid request #3 */
	parcel_init(&rilp);
	request.tech = RADIO_TECH_GPRS;
	request.data_profile = RIL_DATA_PROFILE_DEFAULT;
	request.apn = "test.apn";
	request.username = "phablet";
	request.password = "phablet";
	request.auth_type = RIL_AUTH_BOTH;
	request.protocol = OFONO_GPRS_PROTO_IP;
	result = g_ril_setup_data_call(NULL, &request, &rilp, &error);
	g_assert(result == TRUE);
	g_assert(error.type == OFONO_ERROR_TYPE_NO_ERROR &&
			error.error == 0);
	parcel_free(&rilp);

}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/testgrilmessages/gprs-context: "
			"test invalid SETUP_DATA_CALL requests",
			test_invalid_setup_data_calls);
	g_test_add_func("/testgrilmessages/gprs-context: "
			"test valid SETUP_DATA_CALL requests",
			test_valid_setup_data_calls);

	return g_test_run();
}
