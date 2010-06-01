<?php
/* @(#) $Id: ossec_formats.php,v 1.7 2008/03/03 19:37:25 dcid Exp $ */

/* Copyright (C) 2006-2008 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

/**
 * This file contains the definition of the $log_categories variable that is
 * used to generate the log format pulldown on the search page.
 * 
 * @copyright Copyright (c) 2006-2008, Daniel B. Cid, All rights reserved.
 * @package ossec_web_ui
 * @author  Daniel B. Cid <dcid@ossec.net>
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GNU Public License
 * 
 */

/**
 * This variable is an array keyed on category name, and each element is another
 * array keyed on sub-category name. The values of the subcategory arrays are
 * tags identifying event groups to be used to constrain search results. These
 * tags can be either plain strings or regular expressions to be used in a call
 * to preg_match (minus the enclosing '/' tokens).
 */
$log_categories = array(
	"Syslog" => array(
		"Syslog (all)"           => "syslog"
	,	"Sshd"                   => "sshd"
	,	"Arpwatch"               => "arpwatch"
	,	"Ftpd"                   => "ftpd"
	,	"Pam Unix"               => "pam"
	,	"Proftpd"                => "proftpd"
	,	"Pure-ftpd"              => "pure-ftpd"
	,	"Vsftpd"                 => "vsftpd"
	,	"Sendmail"               => "sendmail"
	,	"Postfix"                => "postfix"
	,	"Imapd"                  => "imapd"
	,	"Vpopmail"               => "vpopmail"
	,	"Spamd"                  => "spamd"
	,	"Horde IMP"              => "horde"
	,	"Smbd"                   => "smbd"
	,	"NFS"                    => "nfs"
	,	"Xinetd"                 => "xinetd"
	,	"Kernel"                 => "kernel"
	,	"Su"                     => "su"
	,	"Cron"                   => "cron"
	,	"Sudo"                   => "sudo"
	,	"PPTP"                   => "pptp"
	,	"Named"                  => "named"
	),

	"Firewall" => array(
		"Firewall"               => "firewall|pix"
	,	"Pix"                    => "pix"
	,	"Netscreen"              => "netscreenfw"
	),

	"Microsoft" => array(
		"Microsoft (all)"        => "windows|msftp|exchange"
	,	"Windows"                => "windows"
	,	"MS Ftp"                 => "msftp"
	,	"Exchange"               => "exchange"
	),

	"Web logs" => array(
		"Web logs (all)"         => "web-log"
	),

	"Squid" => array(
		"Squid (all)"            => "squid"
	),

	"Security devices" => array(
		"Security devices (all)" => "symantec|cisco_vpn|ids"
	,	"Cisco VPN"              => "Cisco VPN"
	,	"Symantec AV"            => "symantec"
	,	"NIDS"                   => "ids"
	)

);

/* EOF */

?>
