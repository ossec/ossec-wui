<?php
/* @(#) $Id: os_lib_handle.php,v 1.9 2008/03/03 19:37:25 dcid Exp $ */

/* Copyright (C) 2006-2008 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */
       
/**
 * This file contains functions dealing with the retrieval of firewall alert
 * related information from an OSSEC installation.
 * 
 * @copyright Copyright (c) 2006-2008, Daniel B. Cid, All rights reserved.
 * @package ossec_web_ui
 * @author  Daniel B. Cid <dcid@ossec.net>
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GNU Public License
 * 
 */

/**
 * Verify that the given configuration items are set. Returns
 * NULL on error.
 *
 * @param unknown_type $ossec_dir
 * @param unknown_type $ossec_max_alerts_per_page
 * @param unknown_type $ossec_search_level
 * @param unknown_type $ossec_search_time
 * @param unknown_type $ossec_refresh_time
 * @return unknown
 */
function os_check_config($ossec_dir, $ossec_max_alerts_per_page,
                         $ossec_search_level, $ossec_search_time,
                         $ossec_refresh_time)
{
    $config_err = "<b class='red'>Configuration error. Missing '%s'.</b><br />";
    
    /* checking each config variable */
    if(!isset($ossec_dir))
    {
        echo sprintf($config_err, '$ossec_dir');
        return(0);
    }

    if(!isset($ossec_max_alerts_per_page))
    {
        echo sprintf($config_err, '$ossec_max_alerts_per_page');
        return(0);
    }

    if(!isset($ossec_search_level))
    {
        echo sprintf($config_err, '$ossec_search_level');
        return(0);
    }

    if(!isset($ossec_search_time))
    {
        echo sprintf($config_err, '$ossec_search_time');
        return(0);
    }

    if(!isset($ossec_refresh_time))
    {
        echo sprintf($config_err, '$ossec_refresh_time');
        return(0);
    }
    
    return(1);
}


/**
 * Set the handle directory and create the ossec handler.
 *
 * @param unknown_type $dir
 * @return unknown
 */
function os_handle_start($dir)
{
    $ossec_handle{'dir'} = NULL;
    $ossec_handle{'agent_dir'} = NULL;
    $ossec_handle{'name'} = NULL;
    $ossec_handle{'error'} = NULL;


    /* 20 minutes */
    $ossec_handle{'notify_time'} = 1200;

    $dh = NULL;
    if($dh = opendir($dir))
    {
        closedir($dh);
        $ossec_handle{'dir'} = $dir;
        $ossec_handle{'agent_dir'} = $dir."/queue/agent-info";
        
        return($ossec_handle);
    }
    return(NULL);
}


/* EOF */
?>
