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

#ifndef __GRILMESSAGES_H
#define __GRILMESSAGES_H

#include <ofono/types.h>

#include "parcel.h"

#ifdef __cplusplus
extern "C" {
#endif

struct setup_data_call_req {
	guint tech;
	guint data_profile;
	gchar *apn;
	gchar *username;
	gchar *password;
	guint auth_type;
	guint protocol;
};

gboolean g_ril_setup_data_call(GRil *gril,
				const struct setup_data_call_req *request,
				struct parcel *rilp, struct ofono_error *error);

struct setup_data_call_reply {
	gint status;
	gint cid;
	gchar *ifname;
	gchar **dns_addresses;
	gchar **gateways;
	gchar **ip_addrs;
};

gboolean g_ril_parse_data_call_reply(GRil *gril,
					struct setup_data_call_reply *reply,
					struct parcel *rilp,
					struct ofono_error *error);


#ifdef __cplusplus
}
#endif

#endif /* __GRILMESSAGES_H */
