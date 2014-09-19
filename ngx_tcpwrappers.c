/*
 * ngx_tcpwrappers.c
 *
 *  Created on: 05.10.2009
 *      Author: Volodymyr Kolesnykov <volodymyr@wildwolf.name>
 */

#include <ngx_http.h>
#include <ngx_inet.h>
#include <tcpd.h>
#include <syslog.h>

/**
 * @brief Default daemon name for libwrap
 */
#define NGX_TCPWRAPPERS_DAEMON "nginx"

#if (NGX_THREADS)
static ngx_mutex_t* libwrap_mutex;
#endif

static int orig_allow_severity;
static int orig_deny_severity;
static int orig_hosts_access_verbose;
static u_char* orig_allow_table = NULL;
static u_char* orig_deny_table  = NULL;

/**
 * @brief Module configuration structure
 */
typedef struct {
	ngx_flag_t enabled;    /**< tcpwrappers on */
	ngx_flag_t thorough;   /**< tcpwrappers_thorough on */
	ngx_str_t daemon;      /**< tcpwrappers_daemon */
	int allow_severity;
	int deny_severity;
	int verbose_access;
	ngx_str_t allow_file;
	ngx_str_t deny_file;
} ngx_http_tcpwrappers_conf_t;

/* Forward declarations */
static ngx_int_t ngx_http_tcpwrappers_handler(ngx_http_request_t* r);
static ngx_int_t ngx_http_tcpwrappers_init(ngx_conf_t* cf);
static void* ngx_http_tcpwrappers_create_loc_conf(ngx_conf_t* cf);
static char* ngx_http_tcpwrappers_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);
static int my_hosts_ctl(char* daemon, ngx_connection_t* conn, char* client_addr, ngx_http_tcpwrappers_conf_t* config);
static int my_hosts_access(char* daemon, ngx_connection_t* conn, ngx_http_tcpwrappers_conf_t* config);

/**
 * @brief Severities for @c tcpwrappers_allow_severity and tcpwrappers_deny_severity
 */
static ngx_conf_enum_t severities[] = {
	{ ngx_string("emerg"),   LOG_EMERG },
	{ ngx_string("alert"),   LOG_ALERT },
	{ ngx_string("crit"),    LOG_CRIT },
	{ ngx_string("err"),     LOG_ERR },
	{ ngx_string("warning"), LOG_WARNING },
	{ ngx_string("notice"),  LOG_NOTICE },
	{ ngx_string("info"),    LOG_INFO },
	{ ngx_string("debug"),   LOG_DEBUG },
	{ ngx_null_string, 0 }
};

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

	{
		ngx_string("tcpwrappers_daemon"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_tcpwrappers_conf_t, daemon),
		NULL
	},

	{
		ngx_string("tcpwrappers_allow_severity"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_enum_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_tcpwrappers_conf_t, allow_severity),
		&severities
	},

	{
		ngx_string("tcpwrappers_deny_severity"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_enum_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_tcpwrappers_conf_t, deny_severity),
		&severities
	},

	{
		ngx_string("tcpwrappers_allow_file"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_tcpwrappers_conf_t, allow_file),
		NULL
	},

	{
		ngx_string("tcpwrappers_deny_file"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_tcpwrappers_conf_t, deny_file),
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
	char* daemon_name;
	unsigned char* p;

	if (1 != config->enabled || !config->daemon.len) {
		return NGX_DECLINED;
	}

	if (
			AF_INET != r->connection->sockaddr->sa_family
#if (NGX_HAVE_INET6)
			&& AF_INET6 != r->connection->sockaddr->sa_family
#endif
		)
	{
		return NGX_DECLINED;
	}

	daemon_name = (char*)alloca(config->daemon.len + 1);
	p = ngx_cpymem(daemon_name, config->daemon.data, config->daemon.len);
	*p = '\0';

	if (1 == config->thorough) {
		res = my_hosts_access(daemon_name, r->connection, config);
	}
	else {
		char* client_addr = STRING_UNKNOWN;
		char addr[NGX_INET6_ADDRSTRLEN+1];

		if (r->connection->addr_text.len) {
			memcpy(addr, r->connection->addr_text.data, r->connection->addr_text.len);
			addr[r->connection->addr_text.len] = 0;
			client_addr = addr;
		}

		res = my_hosts_ctl(daemon_name, r->connection, client_addr, config);
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
 * @sa orig_allow_severity
 * @sa orig_deny_severity
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

	orig_allow_severity       = allow_severity;
	orig_deny_severity        = deny_severity;
	resident                  = 1;
	orig_hosts_access_verbose = hosts_access_verbose;
	orig_allow_table          = (u_char*)hosts_allow_table;
	orig_deny_table           = (u_char*)hosts_deny_table;

	if (NULL != conf) {
		conf->enabled  = NGX_CONF_UNSET;
		conf->thorough = NGX_CONF_UNSET;
		ngx_str_null(&conf->daemon);
		conf->allow_severity = NGX_CONF_UNSET;
		conf->deny_severity  = NGX_CONF_UNSET;
		conf->verbose_access = NGX_CONF_UNSET;
		ngx_str_null(&conf->allow_file);
		ngx_str_null(&conf->deny_file);
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

	ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
	ngx_conf_merge_value(conf->thorough, prev->thorough, 0);
	ngx_conf_merge_str_value(conf->daemon, prev->daemon, NGX_TCPWRAPPERS_DAEMON);
	ngx_conf_merge_value(conf->allow_severity, prev->allow_severity, orig_allow_severity);
	ngx_conf_merge_value(conf->deny_severity,  prev->deny_severity,  orig_deny_severity);
	ngx_conf_merge_value(conf->verbose_access, prev->verbose_access, orig_hosts_access_verbose);

	if (!conf->allow_file.data) {
		if (prev->allow_file.data) {
			conf->allow_file.len  = prev->allow_file.len;
			conf->allow_file.data = prev->allow_file.data;
		}
		else {
			conf->allow_file.len  = strlen((char*)orig_allow_table);
			conf->allow_file.data = orig_allow_table;
		}
	}

	if (!conf->deny_file.data) {
		if (prev->deny_file.data) {
			conf->deny_file.len  = prev->deny_file.len;
			conf->deny_file.data = prev->deny_file.data;
		}
		else {
			conf->deny_file.len  = strlen((char*)orig_deny_table);
			conf->deny_file.data = orig_deny_table;
		}
	}

	return NGX_CONF_OK;
}

/**
 * @param daemon Daemon name
 * @param client_addr Client IP address
 * @return Whether access should be granted
 * @retval 0 No
 * @retval 1 Yes
 */
static int my_hosts_ctl(char* daemon, ngx_connection_t* conn, char* client_addr, ngx_http_tcpwrappers_conf_t* config)
{
	int res;
	char* p;
	char* allow_file;
	char* deny_file;

	p = alloca(config->allow_file.len + config->deny_file.len + 2);
	allow_file = p;

	p = (char*)ngx_cpymem(p, config->allow_file.data, config->allow_file.len);
	*p = 0;
	++p;
	deny_file = p;
	p = (char*)ngx_cpymem(p, config->deny_file.data, config->deny_file.len);
	*p = 0;

	ngx_log_debug4(
		NGX_LOG_DEBUG_HTTP,
		conn->log,
		0,
		"ngx_tcpwrappers: daemon: %s, allow file: %s, deny file: %s, verbosity: %d",
		daemon,
		allow_file,
		deny_file,
		config->verbose_access
	);

#if (NGX_THREADS)
	ngx_mutex_lock(libwrap_mutex);
#endif

	allow_severity       = config->allow_severity;
	deny_severity        = config->deny_severity;
	hosts_access_verbose = config->verbose_access;
	hosts_allow_table    = allow_file;
	hosts_deny_table     = deny_file;

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
static int my_hosts_access(char* daemon, ngx_connection_t* conn, ngx_http_tcpwrappers_conf_t* config)
{
	int res;
	char* p;
	char* allow_file;
	char* deny_file;
	struct request_info request_info;

	p = alloca(config->allow_file.len + config->deny_file.len + 2);
	allow_file = p;

	p = (char*)ngx_cpymem(p, config->allow_file.data, config->allow_file.len);
	*p = 0;
	++p;
	deny_file = p;
	p = (char*)ngx_cpymem(p, config->deny_file.data, config->deny_file.len);
	*p = 0;

	ngx_log_debug4(
		NGX_LOG_DEBUG_HTTP,
		conn->log,
		0,
		"ngx_tcpwrappers: daemon: %s, allow file: %s, deny file: %s, verbosity: %d",
		daemon,
		allow_file,
		deny_file,
		config->verbose_access
	);

#if (NGX_THREADS)
	ngx_mutex_lock(libwrap_mutex);
#endif

	allow_severity       = config->allow_severity;
	deny_severity        = config->deny_severity;
	hosts_access_verbose = config->verbose_access;
	hosts_allow_table    = allow_file;
	hosts_deny_table     = deny_file;

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
