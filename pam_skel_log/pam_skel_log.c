/*
 * Author: rossano at gmail dot com
 * This file is part of the pamskel distribution 
 * (https://gitlab.com/rossanx/pamskel.git).
 * Copyright (c) Rossano Pablo Pinto, 2024.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * ----
 */

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>

/*
 * Authentication realm
 */

int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) 
{
	return PAM_SUCCESS;
}

/*
 * Authentication realm
 */

int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) 
{
	pam_syslog(pamh, LOG_NOTICE, "RPP: message from pam_skel_log.so pam module. YeY !!!!");
	return PAM_SUCCESS;
}
