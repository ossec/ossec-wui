<?php
/* @(#) $Id: os_lib_stats.php,v 1.6 2008/03/03 19:37:25 dcid Exp $ */

/* Copyright (C) 2006-2008 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */
       


/* Internal function to parse alerts. */
function __os_parsestats(&$fp, &$month_hash)
{
    $daily_hash = array();
    
    /* Initializing daily hash */
    $daily_hash{'total'} = 0;
    $daily_hash{'alerts'} = 0;
    $daily_hash{'syscheck'} = 0;
    $daily_hash{'firewall'} = 0;
    

    /* Regexes */
    $global_regex = "/^(\\d+)--(\\d+)--(\\d+)--(\\d+)--(\\d+)$/";
    $rules_regex = "/^(\\d+)-(\\d+)-(\\d+)-(\\d+)$/";

    
    while(!feof($fp)) 
    {
        $buffer = fgets($fp, 1024);
        
        /* Removing new line */
        $buffer = rtrim($buffer);


        /* Getting total number of events/alerts */
        if(preg_match($global_regex, $buffer, $regs))
        {
            $daily_hash{'alerts_by_hour'}[$regs[1]] = $regs[2];
            $daily_hash{'total_by_hour'}[$regs[1]] = $regs[3];
            $daily_hash{'syscheck_by_hour'}[$regs[1]] = $regs[4];
            $daily_hash{'firewall_by_hour'}[$regs[1]] = $regs[5];
            
            $daily_hash{'alerts'}+= $regs[2];
            $daily_hash{'total'}+= $regs[3];
            $daily_hash{'syscheck'}+= $regs[4];
            $daily_hash{'firewall'}+= $regs[5];
        }
        else if(preg_match($rules_regex, $buffer, $regs))
        {
            /* By level */
            if(!isset($daily_hash{'level'}{$regs[3]}))
            {
                $daily_hash{'level'}{$regs[3]} = 0;
            }
            $daily_hash{'level'}{$regs[3]}+= $regs[4];

            if(!isset($month_hash{'level'}{$regs[3]}))
            {
                $month_hash{'level'}{$regs[3]} = 0;
            }
            $month_hash{'level'}{$regs[3]}+= $regs[4];

            /* Bu rule */
            if(!isset($daily_hash{'rule'}{$regs[2]}))
            {
                $daily_hash{'rule'}{$regs[2]} = 0;
            }

            if(!isset($month_hash{'rule'}{$regs[2]}))
            {
                $month_hash{'rule'}{$regs[2]} = 0;
            }

            $daily_hash{'rule'}{$regs[2]}+= $regs[4];
            $month_hash{'rule'}{$regs[2]}+= $regs[4];

        }
        else
        {
            continue;
        }
        
    }

    /* Filling month hash */
    $month_hash{'total'}+= $daily_hash{'total'};
    $month_hash{'alerts'}+= $daily_hash{'alerts'};
    $month_hash{'firewall'}+= $daily_hash{'firewall'};
    $month_hash{'syscheck'}+= $daily_hash{'syscheck'};

    return($daily_hash);
}


function os_getstats($ossec_handle, 
                     $init_time, $final_time)
{
    $stats_list = NULL;
    $stats_count = 1;
    $file_list[0] = NULL;
    $file_count = 0;
    $month_hash = NULL;

    $curr_time = time(0);


    /* Initializing month hash */
    $month_hash{'total'} = 0;
    $month_hash{'alerts'} = 0;
    $month_hash{'firewall'} = 0;
    $month_hash{'syscheck'} = 0;


    /* Getting first file */
    $init_loop = $init_time;
    while($init_loop <= $final_time)
    {
        $fp = false;
        $l_year_month = date('Y/M',$init_loop);
        $l_day = date('d',$init_loop);
        
        
        $file = "stats/totals/".
                $l_year_month."/ossec-totals-".$l_day.".log";

        $log_file = $ossec_handle{'dir'}.'/'.$file;

        
        /* Adding one day */
        $init_loop+=86400;
        $file_count++;
    
    
        /* Opening alert file */
        if( file_exists( $log_file ) ) {
	        $fp = fopen($log_file, 'r');
	        if($fp === false)
	        {
	            continue;
	        }
	
	        $stats_hash = __os_parsestats($fp, $month_hash);
	        if($stats_hash{'total'} != 0)
	        {
	            $stats_list{$l_year_month}{$l_day} = $stats_hash;
	        }
	
	        fclose($fp);
        }

    }

    /* Monthly hash goes to day 0 */
    $stats_list{$l_year_month}{0} = $month_hash;
    
    return($stats_list);
}


?>
