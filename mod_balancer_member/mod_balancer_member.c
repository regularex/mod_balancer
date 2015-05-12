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
 *
 * mod_balancer_member.c - Load Balancer Member for the FreeSWITCH mod_balancer module.
 *
 */


#include <switch.h>

static struct {
	int debug;
    
    int session_count;
    char *ip_addr;
    char *hostname;
    char *cpu;
	char *is_webservice;
    
	char *odbc_dsn;
	char *db_name;
    
	switch_mutex_t *mutex;
	switch_memory_pool_t *pool;
} globals;


/* Prototypes */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_balancer_member_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_balancer_member_load);
SWITCH_MODULE_DEFINITION(mod_balancer_member, mod_balancer_member_load, mod_balancer_member_shutdown, NULL);

SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_is_webservice, globals.is_webservice);

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

static switch_status_t balancer_member_load_config(void)
{
	char *cf = "balancer_member.conf";
	switch_cache_db_handle_t *dbh = NULL;
	switch_xml_t cfg, xml = NULL, param, settings;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
    
	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Could not open config file [%s]\n", cf);
		status = SWITCH_STATUS_SUCCESS;
		goto defaults;
	}
    
	if ((settings = switch_xml_child(cfg, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");
			
			if (!strcasecmp(var, "odbc-dsn") && !zstr(val)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, " is %s\n", val);
				switch_safe_free(globals.odbc_dsn);
				globals.odbc_dsn = strdup(val);
			} else if (!strcasecmp(var, "is_webservice")) {
				globals.is_webservice = val;
			}
		}
	}
	
defaults:
	if (zstr(globals.is_webservice)) {
		set_global_is_webservice("0");
	}
    
	if (globals.odbc_dsn) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Using DSN: %s\n", globals.odbc_dsn);
		if (!(dbh = get_db_handle())) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Error getting DB handle.\n");
			switch_goto_status(SWITCH_STATUS_FALSE, done);
		}
	}
    
done:
	if (xml) {
		switch_xml_free(xml);
	}
    
	return status;
}

void debug_event_handler(switch_event_t *event)
{
	if (!event) {
		return;
	}
    
	/* Print out all event headers, for fun */
	if (event->headers) {
		switch_event_header_t *event_header = NULL;
		for (event_header = event->headers; event_header; event_header = event_header->next) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Header info: %s => %s\n", event_header->name, event_header->value);
        }
    }
}

static switch_bool_t update_balancer_member(const char *hostname, const char *cpu, const char *count)
{
    char *sql = NULL;
    switch_bool_t retval = SWITCH_FALSE;
	switch_cache_db_handle_t *dbh = NULL;
    
    sql = switch_mprintf("UPDATE balancer_members SET cpu_idle = %f, sessions = %d, date = now() WHERE hostname = '%q'", atof(cpu), atoi(count), hostname);
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "SQL was: %s.\n", sql);
    
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

static void event_handler(switch_event_t *event)
{
    const char *count = switch_event_get_header(event, "Session-Count");
    const char *cpu = switch_event_get_header(event, "Idle-CPU");
    const char *hostname = switch_event_get_header(event, "FreeSWITCH-Hostname");
    
	if (!event) {
		return;
	}
    
    if (!update_balancer_member(hostname, cpu, count))
        return;
    
    return;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_balancer_member_load)
{
    //switch_application_interface_t *app_interface;
	//switch_api_interface_t *api_interface;
    switch_status_t status;
    
	memset(&globals, 0, sizeof(globals));
	globals.pool = pool;
    
	switch_mutex_init(&globals.mutex, SWITCH_MUTEX_NESTED, globals.pool);
    
	if ((status = balancer_member_load_config()) != SWITCH_STATUS_SUCCESS) {
		return status;
	}
    
	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
    
	if (switch_event_bind(modname, SWITCH_EVENT_HEARTBEAT, SWITCH_EVENT_SUBCLASS_ANY, event_handler, NULL) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't bind!\n");
		return SWITCH_STATUS_GENERR;
	}
    
	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_balancer_member_shutdown)
{
	//switch_core_remove_state_handler(&event_handler);
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
