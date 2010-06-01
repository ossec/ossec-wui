<?php
/* @(#) $Id: os_lib_firewall.php,v 1.8 2008/03/03 19:37:25 dcid Exp $ */

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
 * Attempts to read the next firewall alert matching any specified constraints
 * from the given file handle.
 *
 * @param unknown_type $fp
 * @param unknown_type $file_month
 * @param unknown_type $curr_time
 * @param unknown_type $init_time
 * @param unknown_type $final_time
 * @param unknown_type $protocol_pattern
 * @param unknown_type $srcip_pattern
 * @param unknown_type $dstip_pattern
 * @param unknown_type $srcport_pattern
 * @param unknown_type $dstport_pattern
 * @param unknown_type $action_pattern
 * @param unknown_type $location_pattern
 * @return unknown
 */
function __os_parsefw(&$fp, $file_month, $curr_time, 
                       $init_time, $final_time, $protocol_pattern,
                       $srcip_pattern, $dstip_pattern,
                       $srcport_pattern, $dstport_pattern,
                       $action_pattern, $location_pattern)
{
    $evt_time = 0;
    $evt_protocol = NULL;
    $evt_location = NULL;
    $evt_action = NULL;
    $evt_srcip = NULL;
    $evt_dstip = NULL;
    $evt_srcport = NULL;
    $evt_dstport = NULL;
    $evt_msg = NULL;
    
    /* Firewall pattern */
    $fwpattern = "/^([0-9]{4}) [a-zA-Z]{3} ([0-9]{2}) ".
                 "([0-9]{2}):([0-9]{2}):([0-9]{2}) ".
                 "([^>]+>\S+) (\w+) (\w+) ([a-zA-Z0-9\._-]+):".
                 "([a-zA-Z0-9_-]+)->([a-zA-Z0-9\._-]+):([a-zA-Z0-9_-]+)$/";
                   
    while(!feof($fp)) 
    {
        $buffer = fgets($fp, 2048);
        $buffer = rtrim($buffer);
       
        if(preg_match($fwpattern, $buffer, $regs))
        {
            $evt_time = mktime($regs[3], $regs[4], $regs[5], 
                               $file_month, $regs[2], $regs[1]);
            $evt_location = $regs[6];
            $evt_action = $regs[7];
            $evt_protocol = $regs[8];
            $evt_srcip = $regs[9];
            $evt_srcport = $regs[10];
            $evt_dstip = $regs[11];
            $evt_dstport = $regs[12];
        }
        else
        {
            continue;
        }
        

        /* Checking if event time is in the timeframe */
        if(($init_time != 0) && ($evt_time < $init_time))
        {
            continue;
        }

        if(($final_time != 0) && ($evt_time > $final_time))
        {
            return(NULL);
        }


        
        /* If we reach here, we got the event */
        $alert_struct{'time'} = $evt_time;
        $alert_struct{'location'} = $evt_location;
        $alert_struct{'action'} = $evt_action;
        $alert_struct{'msg'} = $buffer;
        $alert_struct{'srcip'} = $evt_srcip;
        $alert_struct{'dstip'} = $evt_dstip;
        $alert_struct{'srcport'} = $evt_srcport;
        $alert_struct{'dstport'} = $evt_dstport;
        $alert_struct{'protocol'} = $evt_protocol;

        return($alert_struct);
    }

    return(NULL);
}

/**
 * Return a list of matching firewall alerts based on the given constraints.
 *
 * @param unknown_type $ossec_handle
 * @param unknown_type $search_id
 * @param unknown_type $init_time
 * @param unknown_type $final_time
 * @param unknown_type $max_count
 * @param unknown_type $protocol_pattern
 * @param unknown_type $srcip_pattern
 * @param unknown_type $dstip_pattern
 * @param unknown_type $srcport_pattern
 * @param unknown_type $dstport_pattern
 * @param unknown_type $action_pattern
 * @param unknown_type $location_pattern
 * @return unknown
 */
function os_searchfw($ossec_handle, $search_id,
                     $init_time, $final_time,
                     $max_count, $protocol_pattern,
                     $srcip_pattern, $dstip_pattern,
                     $srcport_pattern, $dstport_pattern,
                     $action_pattern, $location_pattern) 
{
    $alert_list = NULL;
    $alert_count = 1;
    $file_list[0] = NULL;
    $file_count = 0;

    $curr_time = time(0);


    /* Saved values for java script optmization */
    $s_srcip = "-1";
    $s_dstip = "-1";
    $s_srcport = "-1";
    $s_dstport = "-1";


    /* Getting first file */
    $init_loop = $init_time;
    while($init_loop <= $final_time)
    {
        $l_year_month = date('Y/M',$init_loop);
        $l_day = date('d',$init_loop);
        $l_month = date('n', $init_loop);
        
        $file_list[$file_count] = "logs/firewall/".
                                  $l_year_month."/ossec-firewall-".
                                  $l_day.".log";

        /* Adding one day */
        $init_loop+=86400;
        $file_count++;
    }
    
    
    /* Getting each file */
    foreach($file_list as $file)
    {

        // If the file does not exist, it must be gzipped so switch to a
        // compressed stream for reading and try again. If that also fails,
        // abort this log file and continue on to the next one.

        $log_file = $ossec_handle{'dir'}.'/'.$file;
        $fp = @fopen($log_file,'rb');
        if($fp === false) {
            $fp = @fopen("compress.zlib://$log_file.gz", 'rb');
            if($fp === false) { continue; }
        }

        while(1)
        {
            /* Dont get more than max count alerts */
            if($alert_count > $max_count)
            {
                break;
            }
            
            $alert_hash = __os_parsefw($fp, $l_month, $curr_time, $init_time, 
                                       $final_time, $protocol_pattern,
                                       $srcip_pattern, $dstip_pattern,
                                       $srcport_pattern, $dstport_pattern,
                                       $action_pattern, $location_pattern);
            if($alert_hash == NULL)
            {
                break;
            }

            /* Adding information about alert */

            /* Optmizing based on the dstip */
            if($s_dstip != $alert_hash{'dstip'})
            {
                if(!isset($alert_list[0]{'dstips'}{$alert_hash{'dstip'}}))
                {
                    $alert_list[0]{'dstips'}{$alert_hash{'dstip'}} = 1;
                }
                else
                {
                    $alert_list[0]{'dstips'}{$alert_hash{'dstip'}}++;
                }
                $s_dstip = $alert_hash{'dstip'};
                $s_srcip = "-1";

                if($alert_count > 1)
                {
                    $alert_list[$alert_count -1]{'dstip_count'} =
                        $alert_list[0]{'dstips'}
                        {$alert_list[$alert_count -1]{'dstip'}};
                }
            }
            $alert_list[0]{'dstips_total'}{$alert_hash{'dstip'}}++;

            /* Optmizing based on srcip */
            if($s_srcip != $alert_hash{'srcip'})
            {
                if($alert_count > 1)
                {
                    $alert_list[$alert_count -1]{'srcip_count'} =
                        $alert_list[0]{'srcips'}
                        {$alert_list[$alert_count -1]{'srcip'}};
                }
                
                if(!isset($alert_list[0]{'srcips'}{$alert_hash{'srcip'}}))
                {
                    $alert_list[0]{'srcips'}{$alert_hash{'srcip'}} = 1;
                }
                else
                {
                    $alert_list[0]{'srcips'}{$alert_hash{'srcip'}}++;
                }
                $s_srcip = $alert_hash{'srcip'};
            }
            $alert_list[0]{'srcips_total'}{$alert_hash{'srcip'}}++;    
            
            $alert_list[$alert_count] = $alert_hash;
            $alert_count++;
        }


        /* Closing file */
        fclose($fp);
    }

    /* Checking if last entry needs to be marked */
    if($alert_list != NULL)
    {
        $alert_list[$alert_count -1]{'dstip_count'} =
            $alert_list[0]{'dstips'}
            {$alert_list[$alert_count -1]{'dstip'}};

        $alert_list[$alert_count -1]{'srcip_count'} =    
            $alert_list[0]{'srcips'}
            {$alert_list[$alert_count -1]{'srcip'}};
    }
    return($alert_list);
}

?>
