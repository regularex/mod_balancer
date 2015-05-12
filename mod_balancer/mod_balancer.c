/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2012, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 *
 * The Initial Developer of this module is
 * Noel Morgan <noel@vwci.com>
 *
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 *
 */

#include <switch.h>
#define BALANCER_DESC "Load balancing and high-availability for FreeSWITCH."
#define BALANCER_USAGE "<profile>"


static char balancer_members_sql[] =
"CREATE TABLE balancer_members (\n"
"    id serial,"
"    cluster_id integer,"
"    ip_addr varchar(15),"
"    hostname varchar(255),"
"    cpu_idle float,"
"    cpu_idle_threshold int,"
"    sessions integer,"
"    max_sessions integer,"
"    call_timeout integer NOT NULL DEFAULT 30,"
"    bypass_media boolean NOT NULL DEFAULT TRUE,"
"    server_role varchar(32) NOT NULL DEFAULT 'media',"
"    active boolean NOT NULL DEFAULT TRUE,"
"    date timestamp"
");\n";

typedef enum {
    SESSIONS,
    IDLE_CPU,
    BOTH
} strategy_t;

/* Application Globals */
static struct {
	char *odbc_dsn;
	char *db_name;
    char *default_member;
    char *last_checkin_seconds;
    char *cluster_id;
    int cpu_idle_threshold;
    
    strategy_t strategy;
	switch_mutex_t *mutex;
	switch_memory_pool_t *pool;
} globals;


/* Prototypes */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_balancer_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_balancer_load);
SWITCH_MODULE_DEFINITION(mod_balancer, mod_balancer_load, mod_balancer_shutdown, NULL);

SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_default_member, globals.default_member);
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_cluster_id, globals.cluster_id);
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_last_checkin_seconds, globals.last_checkin_seconds);

/* Balancer Cluster Members */
struct cluster_member {
	char ip_addr[255];
	char hostname[255];
	char call_timeout[16];
    int bypass_media;
    int session_count;
    int max_sessions;
	float cpu_idle;
    int cpu_idle_threshold;
    int id;
};
typedef struct cluster_member cluster_member_t;


static int cluster_member_callback(void *pArg, int argc, char **argv, char **columnNames)
{
	cluster_member_t *cbt = (cluster_member_t *) pArg;

	switch_copy_string(cbt->ip_addr, argv[0], 255);
	switch_copy_string(cbt->hostname, argv[1], 255);
	cbt->session_count = atoi(argv[2]);
	cbt->cpu_idle = atof(argv[3]);
    switch_copy_string(cbt->call_timeout, argv[4], 16);
    cbt->bypass_media = atoi(argv[5]);
    cbt->id = atoi(argv[6]);
    
    if (!strlen(argv[0])) {
        cbt->id = 0;
    }

	return 0;
}

static switch_status_t exec_app(switch_core_session_t *session, char *app, char *arg)
{
    switch_application_interface_t *application_interface;
    switch_status_t status = SWITCH_STATUS_FALSE;

    if ((application_interface = switch_loadable_module_get_application_interface(app))) {
        status = switch_core_session_exec(session, application_interface, arg);
        UNPROTECT_INTERFACE(application_interface);
    }

    return status;
}

static switch_cache_db_handle_t *get_db_handle(void)
{
	switch_cache_db_handle_t *dbh = NULL;
	char *dsn;

	if (!zstr(globals.odbc_dsn)) {
		dsn = globals.odbc_dsn;
	} else {
		dsn = globals.db_name;
	}

	if (switch_cache_db_get_db_handle_dsn(&dbh, dsn) != SWITCH_STATUS_SUCCESS) {
		dbh = NULL;
	}

	return dbh;
}

static switch_bool_t execute_sql(char *sql)
{
    switch_bool_t retval = SWITCH_FALSE;
	switch_cache_db_handle_t *dbh = NULL;

	if (globals.odbc_dsn && (dbh = get_db_handle())) {
		if (switch_cache_db_execute_sql(dbh, sql, NULL ) != SWITCH_STATUS_SUCCESS) {
			retval = SWITCH_FALSE;
		} else {
			retval = SWITCH_TRUE;
		}
	}

	switch_cache_db_release_db_handle(&dbh);
    switch_safe_free(sql);

	return retval;
}

static switch_bool_t execute_sql_cluster_member_callback(switch_mutex_t *mutex, char *sql, switch_core_db_callback_func_t callback, void *pdata)
{
	switch_bool_t retval = SWITCH_FALSE;
	switch_cache_db_handle_t *dbh = NULL;
	char *err = NULL;
    
	if (mutex) {
		switch_mutex_lock(mutex);
	}
    
	if (!(dbh = get_db_handle())) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error getting db handle.\n");
		goto done;
	}
    
    switch_cache_db_execute_sql_callback(dbh, sql, callback, pdata, &err);
    
	if (err) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error in SQL: [%s] %s\n", sql, err);
		free(err);
        goto done;
	}
    
    retval = SWITCH_TRUE;
    
done:
	switch_cache_db_release_db_handle(&dbh);
    
	if (mutex) {
		switch_mutex_unlock(mutex);
	}
    
	return retval;
}

char *get_where_clause()
{
    // XXX: do your own here...
    char *where = "";
    
    switch(globals.cpu_idle_threshold)
    {
        case 0:
            break;
        default:
            where = switch_mprintf("AND cpu_idle > %d ", globals.cpu_idle_threshold);
            break;
    }
    
    return where;
}

switch_status_t route_call(switch_core_session_t *session, char *profile, const char *destination_number)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    char *dest = NULL, *bypass_media = NULL;
    cluster_member_t cluster_member;
    switch_channel_t *channel = switch_core_session_get_channel(session);
    
    char *order_by = (globals.strategy == SESSIONS || globals.strategy == BOTH) ? "sessions ASC" : "cpu_idle DESC";
    
    const char *where = get_where_clause();
    
    char *sql = switch_mprintf("SELECT ip_addr, hostname, sessions, cpu_idle, call_timeout, bypass_media, COALESCE(id, 0) as id "
                               "FROM balancer_members WHERE cluster_id = %q AND date > CURRENT_TIMESTAMP - INTERVAL '%q SECONDS' "
                               "%s "
                               "AND cpu_idle > cpu_idle_threshold "
                               "AND sessions <= max_sessions "
                               "AND active = TRUE "
                               "ORDER BY %s LIMIT 1", globals.cluster_id, globals.last_checkin_seconds, where, order_by);
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "SQL was: %s.\n", sql);
    
    memset(&cluster_member, 0, sizeof(cluster_member));
    execute_sql_cluster_member_callback(globals.mutex, sql, cluster_member_callback, &cluster_member);
    switch_safe_free(sql);
    
    if (!cluster_member.id) {
        memset(&cluster_member, 0, sizeof(cluster_member));
        
        sql = switch_mprintf("SELECT ip_addr, hostname, sessions, cpu_idle, call_timeout, bypass_media, id "
                             "FROM balancer_members WHERE cluster_id = %q "
                             "AND hostname = '%q' LIMIT 1", globals.cluster_id, globals.default_member);
        
        execute_sql_cluster_member_callback(globals.mutex, sql, cluster_member_callback, &cluster_member);
        switch_safe_free(sql);
        
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Defaulting to the default balancer cluster member: %s .\n", globals.default_member);
    }
    
    if (!cluster_member.id) {
        goto error;
    }
    
    // XXX: add different types of dest.
    dest = switch_mprintf("sofia/%q/%q@%q", profile, destination_number, cluster_member.ip_addr);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Route dest: was: %s.\n", dest);
    
    bypass_media = (cluster_member.bypass_media) ? "true" : "false";
    
    switch_mutex_lock(globals.mutex);
    switch_channel_set_variable(channel, "call_timeout", cluster_member.call_timeout);
    switch_channel_set_variable(channel, "bypass_media", bypass_media);
    
    if (exec_app(session, "bridge", dest) != SWITCH_STATUS_SUCCESS) {
        goto error;
    }
    
    goto done;
    
error:
    status = SWITCH_STATUS_FALSE;
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error route_call!\n");
    
done:
    switch_mutex_unlock(globals.mutex);
    
    return status;
}

strategy_t set_global_strategy(const char *strategy)
{
    strategy_t global_strategy = SESSIONS;
    
    if (!strcasecmp(strategy, "sessions")) {
        global_strategy = SESSIONS;
    } else if (!strcasecmp(strategy, "both")) {
        global_strategy = BOTH;
    } else if (!strcasecmp(strategy, "idle-cpu")) {
        global_strategy = IDLE_CPU;
    }
    
    return global_strategy;
}

static switch_status_t balancer_load_config(switch_bool_t reload)
{
	char *cf = "balancer.conf";
    char *sql = NULL;
	switch_cache_db_handle_t *dbh = NULL;
	switch_xml_t cfg, xml = NULL, param, settings, cluster_members, cluster_member;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
    
    switch_mutex_lock(globals.mutex);
    
	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Opening of %s failed!\n", cf);
		status = SWITCH_STATUS_TERM;
	}
    
	if ((settings = switch_xml_child(cfg, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *key = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");
			
			if (!strcasecmp(key, "odbc-dsn") && !zstr(val)) {
				switch_safe_free(globals.odbc_dsn);
				globals.odbc_dsn = strdup(val);
			} else if (!strcasecmp(key, "cluster-id")) {
				set_global_cluster_id(val);
			} else if (!strcasecmp(key, "strategy")) {
                globals.strategy = set_global_strategy(val);
			} else if (!strcasecmp(key, "default-member")) {
				set_global_default_member(val);
			} else if (!strcasecmp(key, "cpu-idle-threshold")) {
				globals.cpu_idle_threshold = atoi(val);
			} else if (!strcasecmp(key, "last-checkin-seconds")) {
				set_global_last_checkin_seconds(val);
			}
		}
	}
    
    dbh = get_db_handle();
    if (dbh) {
        if (!reload) {
            char *delete_sql = switch_mprintf("DELETE FROM balancer_members WHERE cluster_id = %q", globals.cluster_id);
            switch_cache_db_test_reactive(dbh, delete_sql, "DROP TABLE balancer_members", balancer_members_sql);
        }
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Cannot open DB!\n");
        status = SWITCH_STATUS_TERM;
        goto done;
    }
    
    if ((cluster_members = switch_xml_child(cfg, "cluster-members"))) {
        for (cluster_member = switch_xml_child(cluster_members, "cluster-member"); cluster_member; cluster_member = cluster_member->next) {
            char *ip_addr = (char *) switch_xml_attr_soft(cluster_member, "ip-addr");
            char *hostname = (char *) switch_xml_attr_soft(cluster_member, "hostname");
            char *call_timeout = (char *) switch_xml_attr_soft(cluster_member, "call-timeout");
            char *bypass_media = (char *) switch_xml_attr_soft(cluster_member, "bypass-media");
            char *server_role = (char *) switch_xml_attr_soft(cluster_member, "server-role");
            char *cpu_idle_threshold = (char *) switch_xml_attr_soft(cluster_member, "cpu-idle-threshold");
            char *max_sessions = (char *) switch_xml_attr_soft(cluster_member, "max-sessions");
            
            if (!zstr(ip_addr) && !zstr(hostname) && !zstr(call_timeout) && !zstr(bypass_media) && !zstr(server_role) && !zstr(cpu_idle_threshold) && !zstr(max_sessions)) {
                
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Balancer member node: ip_addr: %s, hostname: %s added.\n", ip_addr, hostname);
                
                sql = switch_mprintf("INSERT INTO balancer_members (cluster_id, ip_addr, hostname, cpu_idle, cpu_idle_threshold, sessions, max_sessions, call_timeout, bypass_media, server_role, date) "
                                     "VALUES (%s, '%q', '%q', 0.0, %d, 0, %d, '%q', '%q', '%q', now())", globals.cluster_id, ip_addr, hostname, atoi(cpu_idle_threshold), atoi(max_sessions), call_timeout, bypass_media, server_role);
                
                if(!execute_sql(sql)) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error adding balancer_members to DB.\n");
                    return SWITCH_STATUS_GENERR;
                }
            } else {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Problem with balancer member not added.\n");
            }
        }
    }
    
done:
    switch_cache_db_release_db_handle(&dbh);
    switch_mutex_unlock(globals.mutex);
    
    if (xml) {
        switch_xml_free(xml);
    }
    
    return status;
}

SWITCH_STANDARD_APP(mod_balancer_app)
{
    switch_channel_t *channel = switch_core_session_get_channel(session);
	int argc = 0;
	char *argv[2] = { 0 };
	char *in_data = NULL;
    const char *destination_number = NULL;
	char *profile = NULL;
    
	if (zstr(data)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Missing profile name!\n");
		return;
	}
    
    in_data = switch_core_session_strdup(session, data);
    
	if ((argc = switch_separate_string(in_data, ' ', argv, (sizeof(argv) / sizeof(argv[0])))) < 1) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Not enough args [%s]\n", data);
		return;
	}
    
	if (argv[0]) {
		profile = argv[0];
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Profile was: %s.\n", profile);
	} else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "NO ARGV");
    }
    
    if (!(destination_number = switch_channel_get_variable(channel, "destination_number"))) {
        goto error;
    }
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Destination was: %s.\n", destination_number);
    
    if (route_call(session, profile, destination_number))
        goto error;
    
    goto done;
    
error:
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error in mod_balancer!\n");
    
done:
    return;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_balancer_load)
{
	switch_application_interface_t *app_interface;
	switch_status_t status = SWITCH_FALSE;
    
	memset(&globals, 0, sizeof(globals));
	globals.pool = pool;
    
	switch_mutex_init(&globals.mutex, SWITCH_MUTEX_NESTED, globals.pool);
    
	if ((status = balancer_load_config(SWITCH_FALSE)) != SWITCH_STATUS_SUCCESS) {
		return status;
	}
    
	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
    
    SWITCH_ADD_APP(app_interface, "balancer", "Load Balancer", BALANCER_DESC, mod_balancer_app, BALANCER_USAGE, SAF_SUPPORT_NOMEDIA);
    
	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_balancer_shutdown)
{
	switch_safe_free(globals.db_name);
	switch_safe_free(globals.odbc_dsn);
    
	return SWITCH_STATUS_UNLOAD;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet
*/
