/*
 * code based on example lws-minimal-ws-client-echo
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */


#include <stdbool.h>
#include <libwebsockets.h>

#include <lber-int.h>

#include "portable.h"
#include "slap.h"

#define RING_DEPTH 128

struct per_session_data__nymi {
        char flow_controlled;
        uint8_t completed:1;
};

struct vhd_nymi {
        struct lws_context *context;
        struct lws_vhost *vhost;
        struct lws *client_wsi;

        int *interrupted;
        int *options;
        const char **url;
        const char **ads;
        const char **iface;
        int *port;
};

static struct lws_context *context;
static int interrupted, port = 8080, options = 0;
static const char *url = "/", *ads = "localhost", *iface = NULL;
static bool ready = false;
static bool inited = false;
static bool disconnecting = false;
static bool error = false;
static struct per_session_data__nymi *pss;
static struct vhd_nymi *vhd;
static char smsg[1024] = "";
static char lastmsg[1024] = "";

/* pass pointers to shared vars to the protocol */

static const struct lws_protocol_vhost_options pvo_iface = {
        NULL,
        NULL,
        "iface",		/* pvo name */
        (void *)&iface		/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_ads = {
        &pvo_iface,
        NULL,
        "ads",			/* pvo name */
        (void *)&ads		/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_url = {
        &pvo_ads,

        NULL,
        "url",		/* pvo name */
        (void *)&url	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_options = {
        &pvo_url,
        NULL,
        "options",		/* pvo name */
        (void *)&options	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_port = {
        &pvo_options,
        NULL,
        "port",		/* pvo name */
        (void *)&port	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_interrupted = {
        
&pvo_port,
        NULL,
        "interrupted",		/* pvo name */
        (void *)&interrupted	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo = {
        NULL,		/* "next" pvo linked-list */
        &pvo_interrupted,	/* "child" pvo linked-list */
        "nymi-client",	/* protocol name we belong to on this vhost */
        ""		/* ignored */
};

static const struct lws_extension extensions[] = {
        {
                "permessage-deflate",
                lws_extension_callback_pm_deflate,
                "permessage-deflate"
                 "; client_no_context_takeover"
                 "; client_max_window_bits"
        },
        { NULL, NULL, NULL /* terminator */ }
};

void sigint_handler(int sig)
{
        interrupted = 1;
}

static int
connect_client(struct vhd_nymi *convhd)
{
	if (inited)
	{
		Debug( LDAP_DEBUG_ANY, "Nymi: Already connected, ignoring connection request\n", 0, 0, 0);
		return 1;
	}

        struct lws_client_connect_info i;
        char host[128];

	Debug( LDAP_DEBUG_ANY, "Nymi: connect_client start\n", 0, 0, 0 );

        lws_snprintf(host, sizeof(host), "%s:%u", *vhd->ads, *vhd->port);

        memset(&i, 0, sizeof(i));

        i.context = convhd->context;
        i.port = *convhd->port;
        i.address = *convhd->ads;
        i.path = *convhd->url;
        i.host = host;
        i.origin = host;
        i.ssl_connection = 0;
        if ((*convhd->options) & 2)
                i.ssl_connection |= LCCSCF_USE_SSL;
        i.vhost = convhd->vhost;
        i.iface = *convhd->iface;
        i.pwsi = &convhd->client_wsi;

        Debug( LDAP_DEBUG_ANY, "Nymi: connecting to %s:%d/%s\n", i.address, i.port, i.path);

	struct lws* retlws = NULL;
        retlws = lws_client_connect_via_info(&i);

	Debug( LDAP_DEBUG_ANY, "Nymi: got connection WSI\n", 0, 0, 0 );
	return (retlws != NULL ? 1 : 0);
}

static void
schedule_callback(struct lws *wsi, int reason, int secs)
{
        lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
                lws_get_protocol(wsi), reason, secs);
}

static int
callback_nymi(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
	if (!pss)
        	pss = (struct per_session_data__nymi *)user;
	if (!vhd)
        	vhd = (struct vhd_nymi *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));

        int n, m, flags;

        switch (reason) {

        case LWS_CALLBACK_PROTOCOL_INIT:
		Debug( LDAP_DEBUG_ANY, "Nymi: LWS_CALLBACK_PROTOCOL_INIT\n", 0, 0, 0);


		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
                                lws_get_protocol(wsi),
                                sizeof(struct vhd_nymi));
		if (!vhd)
                        return -1;

                vhd->context = lws_get_context(wsi);
                vhd->vhost = lws_get_vhost(wsi);

		// Get websocket config options
                vhd->interrupted = (int *)lws_pvo_search(
                        (const struct lws_protocol_vhost_options *)in,
                        "interrupted")->value;
                vhd->port = (int *)lws_pvo_search(
                        (const struct lws_protocol_vhost_options *)in,
                        "port")->value;
                vhd->options = (int *)lws_pvo_search(
                        (const struct lws_protocol_vhost_options *)in,
                        "options")->value;
                vhd->ads = (const char **)lws_pvo_search(
                        (const struct lws_protocol_vhost_options *)in,
                        "ads")->value;
                vhd->url = (const char **)lws_pvo_search(
                        (const struct lws_protocol_vhost_options *)in,
                        "url")->value;
                vhd->iface = (const char **)lws_pvo_search(
                        (const struct lws_protocol_vhost_options *)in,
                        "iface")->value;

        	if (connect_client(vhd))
		{
			Debug( LDAP_DEBUG_ANY, "Nymi: Scheduling user callback\n", 0, 0, 0);
        	        schedule_callback(vhd->client_wsi, LWS_CALLBACK_USER, 1);
		}
		
		inited = true;

		Debug( LDAP_DEBUG_ANY, "Nymi: LWS_CALLBACK_PROTOCOL_INIT Complete\n", 0, 0, 0);
                break;

        case LWS_CALLBACK_CLIENT_ESTABLISHED:
                Debug( LDAP_DEBUG_ANY, "Nymi: LWS_CALLBACK_CLIENT_ESTABLISHED\n", 0, 0, 0);
                ready = true;
		Debug( LDAP_DEBUG_ANY, "Nymi: LWS_CALLBACK_CLIENT_ESTABLISHED Complete\n", 0, 0, 0);
                break;

        case LWS_CALLBACK_CLIENT_WRITEABLE:
                Debug( LDAP_DEBUG_ANY, "Nymi: LWS_CALLBACK_CLIENT_WRITEABLE\n", 0, 0, 0);

		if (strlen(smsg) == 0) {
			Debug( LDAP_DEBUG_ANY, "Nymi: nothing waiting to be written\n", 0, 0, 0);
			break;
		}

		flags = lws_write_ws_flags( LWS_WRITE_TEXT, 1, 1 );

                /* notice we allowed for LWS_PRE in the payload */
		Debug( LDAP_DEBUG_ANY, "Nymi: writing [%s] to websocket\n", smsg, 0, 0);
                m = lws_write(wsi, (smsg), strlen(smsg), flags);
                if (m < strlen(smsg)) {
                        Debug( LDAP_DEBUG_ANY, "Nymi: ERROR %d writing to ws socket\n", m, 0, 0);
                        return -1;
                }

                Debug( LDAP_DEBUG_ANY, "Nymi: wrote %d bytes to websocket\n", m, 0, 0);

		memset(smsg, 0, sizeof(char)*1024);

                pss->completed = 1;
                Debug( LDAP_DEBUG_ANY, "Nymi: LWS_CALLBACK_CLIENT_WRITEABLE Complete\n", 0, 0, 0);
		
		lws_callback_on_writable(vhd->client_wsi);

                break;

        case LWS_CALLBACK_CLIENT_RECEIVE:

                Debug( LDAP_DEBUG_ANY, "Nymi: LWS_CALLBACK_CLIENT_RECEIVE: length %d, remaining %d\n", (int)len, (int)lws_remaining_packet_payload(wsi), 0);

                // lwsl_hexdump_notice(in, len);

		Debug( LDAP_DEBUG_ANY, "Nymi: Payload: %s\n", in, 0, 0);

	        // Check for errors
	        if (strstr(in, "\"status\":5100") != NULL)
	        {
	                Debug( LDAP_DEBUG_ANY, "Nymi: Got payload with BLE error, ignoring\n", 0, 0, 0 );
	                break;
	        }
	
	        if (strstr(in, "\"status\":0") == NULL)
	        {
	                Debug( LDAP_DEBUG_ANY, "Nymi: Got payload with error\n", 0, 0, 0 );
			error =true;
			break;
	        }
	
	        // Messages that we might handle at some point, but ignore for now
	
	        if (strstr(in, "\"operation\":\"presence\"") != NULL)
	        {
	                Debug( LDAP_DEBUG_ANY, "Nymi: Got presence notification, ignoring\n", 0, 0, 0 );
	                break;
	        }
	
	        strncpy (lastmsg, in, 1023);

		/*
                if (!pss->flow_controlled && n < 3) {
                        pss->flow_controlled = 1;
                        lws_rx_flow_control(wsi, 0);
                }
		*/

		break;

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
                Debug( LDAP_DEBUG_ANY, "Nymi: CLIENT_CONNECTION_ERROR: %s\n", in ? (char *)in : "(null)", 0, 0);
                vhd->client_wsi = NULL;
                if (!*vhd->interrupted)
                        *vhd->interrupted = 3;
                lws_cancel_service(lws_get_context(wsi));
                break;

        case LWS_CALLBACK_CLIENT_CLOSED:
                Debug( LDAP_DEBUG_ANY, "Nymi: LWS_CALLBACK_CLIENT_CLOSED\n", 0, 0, 0);
                vhd->client_wsi = NULL;
                if (!*vhd->interrupted)
                        *vhd->interrupted = 1 + pss->completed;
                lws_cancel_service(lws_get_context(wsi));
                break;

        default:
                break;
        }

	Debug( LDAP_DEBUG_ANY, "Nymi: LWS_CALLBACK_CLIENT_WRITEABLE complete\n", 0, 0, 0 );
        return 0;
}

int
destroy_protocol_nymi(struct lws_context *context)
{
        return 0;
}

static struct lws_protocols protocols[] = {
        { \
                "nymi-client", \
                callback_nymi, \
                sizeof(struct per_session_data__nymi), \
                1024, \
                0, NULL, 0 \
        },
        { NULL, NULL, 0, 0 } /* terminator */
};


static void
disconnect() {
	Debug( LDAP_DEBUG_ANY, "Nymi: disconnecting wesocket\n", 0, 0, 0 );
	inited = false;
	ready = false;
        lws_context_destroy(context);
}

static bool
waitfordata(char* targetmsg) {
	int time = 0;
	while (true)
	{
		Debug( LDAP_DEBUG_ANY, "Nymi: checking for new data on websocket\n", 0, 0, 0 );
		// Make sure the websocket isn't closed or closing
		if (lws_service(context, 0) || interrupted)
	        {
	        	lws_context_destroy(context);
	        	Debug ( LDAP_DEBUG_ANY, "Nymi: socket closed (%d)\n", interrupted, 0, 0);
			disconnect();
			return false;
		}
	
		if (error)
			return false;
		
		if (strlen(lastmsg) == 0)
		{	
			Debug( LDAP_DEBUG_ANY, "Nymi: No message during waitfordata\n", 0, 0, 0 );
			sleep(1);
			Debug( LDAP_DEBUG_ANY, "Nymi: done sleeping, looking for new message\n", 0, 0, 0 );
			time++;
			if (time > 15)
			{
				Debug( LDAP_DEBUG_ANY, "Nymi: timeout waiting for response to request\n", 0, 0, 0 );
				return false;
			}
			continue;
		}

		Debug ( LDAP_DEBUG_ANY, "Nymi: got a valid message [%s], checking if it's the current target\n", lastmsg, 0, 0 );
	
		if (strstr(lastmsg, targetmsg) != NULL)
		{
			Debug ( LDAP_DEBUG_ANY, "Nymi: found target message\n", 0, 0, 0 );
			return true;
		}
		else
		{
			time = 0;
			Debug ( LDAP_DEBUG_ANY, "Nymi: not target\n", 0, 0, 0 );
		}
	}
}

static void
writemsg(char* message)
{
	Debug( LDAP_DEBUG_ANY, "Nymi: sending message on websocket: %s\n", message, 0, 0 );

	lws_strncpy(smsg, message, 1024);
	lws_callback_on_writable(vhd->client_wsi);
}

void
getJson(char* key, char* value)
{
	Debug( LDAP_DEBUG_ANY, "Nymi: getJson started with %s and %s\n", key, lastmsg, 0 );

	char* keyloc = strstr(lastmsg, key);
	if (keyloc == NULL)
	{
		value = NULL;
		Debug( LDAP_DEBUG_ANY, "Nymi: getJson failed to find key\n", 0, 0, 0 );
		return;
	}
	char* begin = strchr(keyloc, '\"') + 3;
	char* end = strchr(begin, '\"');

	Debug( LDAP_DEBUG_ANY, "Nymi: begin %p, end %p, %s\n", begin, end, lastmsg );
	strncpy(value, begin, end - begin);
}

bool
getNameFromCN(Operation* op, char* usercn, char* samname)
{
	Debug( LDAP_DEBUG_ANY, "Nymi: getNameFromCN started\n", 0, 0, 0);

	Operation searchop;
	memset(&searchop, 0, sizeof(Operation));
	// Create enoded values and BER object
        BerElementBuffer berbuf;
        BerElement *ber = (BerElement *)&berbuf;
        ber_init2( ber, NULL, LBER_USE_DER );
	ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );

	struct berval base, ls_scope, ls_deref, ls_slimit, ls_tlimit, ls_attronly;
	ls_scope.bv_val = LDAP_SCOPE_ONELEVEL;
	ls_scope.bv_len = sizeof(int);


	if ( ber_scanf( op->o_ber, "{miiiib}", &base, &op->ors_scope, &op->ors_deref, &op->ors_slimit, &op->ors_tlimit, &op->ors_attrsonly ) == LBER_ERROR )
        {
		return false;
        }

 	searchop.o_ber = ber;


	// Copy details from bind operation
	searchop.o_hdr = op->o_hdr;

	Debug( LDAP_DEBUG_ANY, "Nymi: defining search options\n", 0, 0, 0);

	// Set search options
	searchop.ors_scope = LDAP_SCOPE_ONELEVEL;
	searchop.ors_deref = LDAP_DEREF_NEVER;
	searchop.ors_slimit = 1024;
	searchop.ors_tlimit = 30;
	searchop.ors_attrsonly = 1;
	//searchop->ors_limit.
	Debug( LDAP_DEBUG_ANY, "Nymi: creating attributes\n", 0, 0, 0);
	AttributeName* samval;
	samval = malloc (sizeof(AttributeName));
	//memset(samval, 0, sizeof(AttributeName));
	samval->an_name.bv_val = "sAMAccountName";
	samval->an_name.bv_len = strlen("sAMAccountName");
	searchop.ors_attrs = samval;
	Debug( LDAP_DEBUG_ANY, "Nymi: creating search filter\n", 0, 0, 0);
	char filterstr[1024];
	sprintf(filterstr, "(cn=%s)", usercn);
	searchop.ors_filterstr.bv_val = filterstr;
	searchop.ors_filterstr.bv_len = strlen(filterstr);

	Debug ( LDAP_DEBUG_ANY, "Nymi: attribute %s with filter %s\n", searchop.ors_attrs->an_name.bv_val, searchop.ors_filterstr.bv_val, 0);

	SlapReply reply;
	
	int rc = do_search (&searchop, &reply);

	Debug( LDAP_DEBUG_ANY, "Nymi: do_search returned %d\n", rc, 0, 0);
	
	lws_strncpy(samname, "mike", 128);

	//memset(&searchop, 0, sizeof(Operation));
	//memset(&reply, 0, sizeof(SlapReply));
	//memset(samval, 0, sizeof(AttributeName));
	SLAP_FREE(ber->ber_buf);
	free(samval);
}

bool
nymiauth(Operation* op, char* peeraddress)
{
	Debug( LDAP_DEBUG_ANY, "Nymi: using Agent %s and NES %s\n", nymi_agent, nymi_nes, 0 );

	char* userdn = op->o_req_dn.bv_val;
	ads = nymi_agent;

        struct lws_context_creation_info info;
        const char *p;
	char bandID[18] = "";
        int n, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_DEBUG;

        lws_set_log_level(logs, lwsl_emit_syslog);

        memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
        info.port = CONTEXT_PORT_NO_LISTEN;
        info.protocols = protocols;
        info.pvo = &pvo;
        info.pt_serv_buf_size = 32 * 1024;
//        info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT | LWS_SERVER_OPTION_VALIDATE_UTF8;
        info.options = LWS_SERVER_OPTION_VALIDATE_UTF8;
        info.fd_limit_per_thread = 3;
        signal(SIGINT, sigint_handler);
        context = lws_create_context(&info);

	if (!context) {
                Debug( LDAP_DEBUG_ANY, "Nymi: lws init failed\n", 0, 0, 0 );
                return false;
        }
	Debug( LDAP_DEBUG_ANY, "Nymi: lws init successful\n", 0, 0, 0 );

	int timeout = 0;
	while (timeout < 20)
	{	
		lws_service(context, 0);
        	if (!ready)
		{
			Debug( LDAP_DEBUG_ANY, "Nymi: websocket not connected, waiting...\n", 0, 0, 0 );
        	        sleep(1);
			timeout++;
			continue;
		}
		else
			break;
	}

	Debug( LDAP_DEBUG_ANY, "Nymi: starting authentication attempt\n", 0, 0, 0 );

	char command[1024];

        lws_snprintf (command, 1024, "{\"operation\":\"subscribe_endpoint\",\"exchange\":\"%s\",\"payload\":{\"endpoint_id\":\"%s\"}}", userdn, peeraddress);
	writemsg(command);
	while (!waitfordata("ble_ready") || error)
	{
		if (error)
		{
			error = false;
			disconnect();
			return false;
		}
	}
	memset(lastmsg, 0, sizeof(char)*1024);

	Debug ( LDAP_DEBUG_ANY, "Nymi: Exctracting username from request user DN [%s]\n", userdn, 0, 0 );

	// Get username from DN for NES lookup
	char* i = strchr(userdn, '=');
	char* j = strchr(userdn, ',');
	Debug( LDAP_DEBUG_ANY, "Nymi: i %p, j %p, diff %d\n", i, j, j-i-1 );
	if (i == NULL || j == NULL)
	{
		Debug( LDAP_DEBUG_ANY, "Nymi: Unable to parse user DN (i %p, j %p)\n", i, j, 0 );
		disconnect();
		return false;
	}

	char usercn[1024];
	strncpy(usercn, i + 1, j - i - 1);
	usercn[j-i-1] = 0;

	Debug ( LDAP_DEBUG_ANY, "Nymi: looking up windows account name for common name %s\n", usercn, 0, 0 );

	char username[128];
	if (!getNameFromCN(op, usercn, username))
	{
                        error = false;
                        disconnect();
                        return false;
        }
        memset(lastmsg, 0, sizeof(char)*1024);

	Debug ( LDAP_DEBUG_ANY, "Nymi: looking up Nymi Band ID for user %s\n", username, 0, 0 );
	
	lws_snprintf (command, 1024, "{\"operation\":\"lookup\",\"exchange\":\"%s\",\"payload\":{\"query\":{\"Username\":\"%s\",\"Domain\":\"LAB\"},\"lookup_keys\":[\"NymiBandID\"]}}", userdn, username);
        writemsg(command);

        if (!waitfordata("lookup") || error)
	{
			error = false;
                        disconnect();
                        return false;
        }

	getJson("NymiBandID", &bandID);

	Debug( LDAP_DEBUG_ANY, "Nymi: got Nymi Band ID %s for user %s\n", bandID, username, 0 );

	memset(lastmsg, 0, sizeof(char)*1024);

        lws_snprintf (command, 1024, "{\"operation\":\"assert_identity\",\"exchange\":\"%s\",\"payload\":{\"assert_type\":\"assert_user\",\"device\":\"%s\"}}", userdn, bandID);
        writemsg(command);

        if (!waitfordata("assert_identity") || error)
        {
		error = false;
                disconnect();
                return false;
        }
	memset(lastmsg, 0, sizeof(char)*1024);
 
	Debug( LDAP_DEBUG_ANY, "Nymi: disconnecting websocket\n", 0, 0, 0 );
	disconnect();

	return true;
}

