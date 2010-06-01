<?php
/* @(#) $Id: os_lib_agent.php,v 1.9 2008/03/03 19:37:25 dcid Exp $ */

/* Copyright (C) 2006-2008 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */
       

/**
 * This file contains functions dealing with the retrieval of agent-related
 * information from an OSSEC installation.
 * 
 * @copyright Copyright (c) 2006-2008, Daniel B. Cid, All rights reserved.
 * @package ossec_web_ui
 * @author  Daniel B. Cid <dcid@ossec.net>
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GNU Public License
 * 
 */

/**
 * Get agent operating system information
 * 
 * Returns as string containing operating system information from the given
 * file, which should be the full path to an agent information file located
 * in $OSSEC_HOME/queue/agent-info. The returned string will be in a format
 * similar to the output of 'uname -a' on a linux system.
 *
 * @param string $agent_file
 *   The agent file from which to read operating system information.
 * @return string
 *   The operating system information found in the given agent file.
 */
function __os_getagentos($agent_file)
{
    $fp = fopen($agent_file, "r");
    if($fp === FALSE)
    {
        return("No system info available");
    }
    
    $buffer = fgets($fp, 1024);
    $buffer = rtrim($buffer);
    
    fclose($fp);

    return($buffer);
}

/**
 * Get an array of agent information.
 * 
 * Returns an array of agent information, one element per agent. Each element
 * is an array containing the following keys:
 * 
 * change_time - Time agent was last heard from<br/>
 * name        - Agent name<br/>
 * ip          - Agent IP address<br/>
 * os          - Agent OS Information<br/>
 * connected   - True if change_time is not older than hardcoded value of 20 minutes.
 * 
 * @param array $ossec_handle
 *   Array of information representing an OSSEC installation.
 * @return array
 *   Array of agent information, one element per agent.
 */
function os_getagents($ossec_handle)
{
    $dh = NULL;
    $file = NULL;
    $agent_list = NULL;
    $agent_count = 0;

    /* Checking if agent_dir is set */
    if(!isset($ossec_handle{'agent_dir'})||($ossec_handle{'agent_dir'}==NULL))
    {
        $ossec_handle{'error'} = "Unable to open agent dir: ".
                                  $ossec_handle{'agent_dir'};
        return(NULL);
    }

    $agent_list[$agent_count]{'change_time'} = time();;
    $agent_list[$agent_count]{'name'} = "ossec-server";
    $agent_list[$agent_count]{'ip'} = "127.0.0.1";
    $agent_list[$agent_count]{'os'} = `uname -a`;
    $agent_list[$agent_count]{'connected'} = 1;
    $agent_count++;
    
    /* Getting all agent files */
    if(@$dh = opendir($ossec_handle{'agent_dir'}))
    {
        while(($file = readdir($dh)) !== false)
        {
            $name = "";
            $ip = "";
            $split_error = 0;
            $tmp_file = $file;
            
            if(($file == ".") || ($file == ".."))
            {
                continue;
            }

            /* Splitting the file. We may have multiple "-". */
            while(1)
            {
                @list($_name, $_ip) = split("-", $tmp_file, 2);
                
                /* Nothing more to split */
                if(!isset($_name) || !isset($_ip))
                {
                    break;
                }

                if($name != "")
                {
                    $name = $name."-".$_name;
                }
                else
                {
                    $name = $_name;
                }
                $ip = $_ip;
                $tmp_file = $_ip;
            }

            /* If name or ip is not set, keep going.. */
            if(($name == "") || ($ip == ""))
            {
                continue;
            }

            $fmtime = filemtime($ossec_handle{'agent_dir'}.'/'.$file);
            
            /* If false, file does not exist */
            if($fmtime == FALSE)
            {
                continue;
            }
            
            $agent_list[$agent_count]{'change_time'} = $fmtime;
            $agent_list[$agent_count]{'name'} = $name;
            $agent_list[$agent_count]{'ip'} = $ip;
            $agent_list[$agent_count]{'os'} = 
                        __os_getagentos($ossec_handle{'agent_dir'}.'/'.$file);
            if((time(0) - $fmtime) < $ossec_handle{'notify_time'})
            {
                $agent_list[$agent_count]{'connected'} = 1;
            }
            else
            {
                $agent_list[$agent_count]{'connected'} = 0;
            }
            $agent_count++;
        }
        closedir($dh);
        return($agent_list);
    }

    $ossec_handle{'error'} = "Unable to open agent dir: ".
                             $ossec_handle{'agent_dir'};
    return(NULL);
}


?>
