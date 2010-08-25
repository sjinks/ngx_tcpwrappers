/*
 * ngx_tcpwrappers.c
 *
 *  Created on: 05.10.2009
 *      Author: Vladimir Kolesnikov <vladimir@extrememember.com>
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stddef.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/syslog.h>
#include <tcpd.h>

/**
 * @brief Daemon name for libwrap
 */
#define NGX_TCPWRAPPERS_DAEMON "nginx"

#if (NGX_THREADS)
static ngx_mutex_t* libwrap_mutex;
#endif

/**
 * @param daemon Daemon name
 * @param client_addr Client IP address
 * @return Whether access should be granted
 * @retval 0 No
 * @retval 1 Yes
 */
static int my_hosts_ctl(char* daemon, char* client_addr)
{
	int res;

#if (NGX_THREADS)
	ngx_mutex_lock(libwrap_mutex);
#endif

	res = hosts_ctl(daemon, "", client_addr, "");

#if (NGX_THREADS)
	ngx_mutex_unlock(libwrap_mutex);
#endif
	return res;
}

/**
 * @param daemon Daemon name
 * @param conn nginx connection structure
 * @return Whether access should be granted
 * @retval 0 No
 * @retval 1 Yes
 */
static int my_hosts_access(char* daemon, ngx_connection_t* conn)
{
	int res;
	struct request_info request_info;

#if (NGX_THREADS)
	ngx_mutex_lock(libwrap_mutex);
#endif

	request_init(
		&request_info,
		RQ_DAEMON, daemon,
		RQ_USER, STRING_UNKNOWN,
		RQ_CLIENT_SIN, conn->local_sockaddr,
		RQ_SERVER_SIN, conn->sockaddr,
		RQ_FILE, conn->fd,
		NULL
	);

	fromhost(&request_info);

	res = hosts_access(&request_info);

#if (NGX_THREADS)
	ngx_mutex_unlock(libwrap_mutex);
#endif
	return res;
}

/**
 * @brief Module configuration structure
 */
typedef struct {
	ngx_flag_t enabled;    /**< tcpwrappers on */
	ngx_flag_t thorough;   /**< tcpwrappers_thorough on */
} ngx_http_tcpwrappers_conf_t;

static ngx_int_t ngx_http_tcpwrappers_handler(ngx_http_request_t* r);
static ngx_int_t ngx_http_tcpwrappers_init(ngx_conf_t* cf);
static void* ngx_http_tcpwrappers_create_loc_conf(ngx_conf_t* cf);
static char* ngx_http_tcpwrappers_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);

/**
 * @brief Configuration directives
 */
static ngx_command_t ngx_http_tcpwrappers_commands[] = {
	{
		ngx_string("tcpwrappers"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_tcpwrappers_conf_t, enabled),
		NULL
	},
	{
		ngx_string("tcpwrappers_thorough"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_tcpwrappers_conf_t, thorough),
		NULL
	},
	ngx_null_command
};

/**
 * @brief Module context
 */
static ngx_http_module_t ngx_http_tcpwrappers_module_ctx = {
	NULL,                                  /* preconfiguration */
	ngx_http_tcpwrappers_init,             /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_http_tcpwrappers_create_loc_conf,  /* create location configuration */
	ngx_http_tcpwrappers_merge_loc_conf    /* merge location configuration */
};

/**
 * @brief Module declaration
 */
ngx_module_t ngx_tcpwrappers_module = {
	NGX_MODULE_V1,
	&ngx_http_tcpwrappers_module_ctx,      /* module context */
	ngx_http_tcpwrappers_commands,         /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};

/**
 * @brief Access control handler
 * @param r Request
 * @return Whether access is allowed
 * @retval NGX_DECLINED Don't know
 * @retval NGX_OK Yes
 * @retval NGX_HTTP_FORBIDDEN No
 */
static ngx_int_t ngx_http_tcpwrappers_handler(ngx_http_request_t* r)
{
	ngx_http_tcpwrappers_conf_t* config = ngx_http_get_module_loc_conf(r, ngx_tcpwrappers_module);
	int res;

	if (1 != config->enabled) {
		return NGX_DECLINED;
	}

	if (AF_INET != r->connection->sockaddr->sa_family) {
		return NGX_DECLINED;
	}

	if (1 == config->thorough) {
		res = my_hosts_access(NGX_TCPWRAPPERS_DAEMON, r->connection);
	}
	else {
		char* client_addr = STRING_UNKNOWN;
		char addr[INET_ADDRSTRLEN];
		struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;

		if (NULL != inet_ntop(AF_INET, &sin->sin_addr, addr, INET_ADDRSTRLEN)) {
			client_addr = addr;
		}

		res = my_hosts_ctl(NGX_TCPWRAPPERS_DAEMON, client_addr);
	}

	if (!res) {
		ngx_http_core_loc_conf_t* clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
		if (NGX_HTTP_SATISFY_ALL == clcf->satisfy) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "access forbidden by tcpwrappers");
		}

		return NGX_HTTP_FORBIDDEN;
	}

	return NGX_OK;
}

/**
 * @brief Initializes tcpwrappers module by installing a handler for the access phase
 * @param cf nginx configuration structure
 * @return Whether initialization succeeded
 * @retval NGX_OK Yes
 * @retval NGX_ERROR No
 */
static ngx_int_t ngx_http_tcpwrappers_init(ngx_conf_t* cf)
{
	ngx_http_core_main_conf_t* cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	ngx_http_handler_pt* h;

#if (NGX_THREADS)
	libwrap_mutex = ngx_mutex_init(cf->log, 0);
	if (NULL == libwrap_mutex) {
		return NGX_ERROR;
	}

	/* TODO: Destroy mutex somewhere */
#endif

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (NULL == h) {
#if (NGX_THREADS)
		ngx_mutex_destroy(libwrap_mutex);
#endif
		return NGX_ERROR;
	}

	*h = ngx_http_tcpwrappers_handler;
	return NGX_OK;
}

/**
 * @brief Creates location configuration
 * @param cf
 * @return Pointer to the configuration block
 */
static void* ngx_http_tcpwrappers_create_loc_conf(ngx_conf_t* cf)
{
	ngx_http_tcpwrappers_conf_t* conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_tcpwrappers_conf_t));
	if (NULL != conf) {
		conf->enabled  = NGX_CONF_UNSET;
		conf->thorough = NGX_CONF_UNSET;
	}

	return conf;
}

/**
 * @brief Merges location configuration
 * @param cf
 * @param parent Parent location configuration
 * @param child Child (current) location configuration (to be merged with @c parent)
 * @return Whether merge is successful
 * @retval NGX_CONF_OK Yes
 * @retval NGX_CONF_ERROR No
 */
static char* ngx_http_tcpwrappers_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child)
{
	ngx_http_tcpwrappers_conf_t* prev = (ngx_http_tcpwrappers_conf_t*)parent;
	ngx_http_tcpwrappers_conf_t* conf = (ngx_http_tcpwrappers_conf_t*)child;

	if (NGX_CONF_UNSET == conf->enabled) {
		conf->enabled = prev->enabled;
	}

	if (NGX_CONF_UNSET == conf->thorough) {
		conf->thorough = prev->thorough;
	}

	return NGX_CONF_OK;
}
