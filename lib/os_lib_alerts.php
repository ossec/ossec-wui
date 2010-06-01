<?php
/* @(#) $Id: os_lib_alerts.php,v 1.17 2008/03/03 19:37:25 dcid Exp $ */

/* Copyright (C) 2006-2008 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

/**
 * This file contains functions dealing with the retrieval of alert-related
 * information from an OSSEC installation.
 * 
 * @copyright Copyright (c) 2006-2008, Daniel B. Cid, All rights reserved.
 * @package ossec_web_ui
 * @author  Daniel B. Cid <dcid@ossec.net>
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GNU Public License
 * 
 */

require_once 'Ossec/Alert.php';
require_once 'Ossec/AlertList.php';

/**
 * Formats the given alerts into HTML and writes the result to the given
 * file path.
 *
 * @param string $out_file
 *   Full path to output file.
 * @param Ossec_AlertList $alert_list
 */
//TODO: This can probably be a method of AlertList
function __os_createresults($out_file, $alert_list)
{
    /* Opening output file */
    $fp = fopen($out_file, "w");
    if(!$fp) {
        return(NULL);
    }
    fwrite( $fp, $alert_list->toHTML() );
}

/**
 * Attempts to read the next alert matching any specified constraints from the
 * given file handle.
 *
 * @param resource $fp
 *   An open filehandle from which to read alerts.
 * @param integer $curr_time
 *   Unix timestamp representing the current time. Currently unused.
 * @param integer $init_time
 *   Unix timestamp used to constrain the list of retrieved alerts to those
 *   which occur AFTER the given time.
 * @param integer $final_time
 *   Unix timestamp used to constrain the list of retrieved alerts to those
 *   which occur BEFORE the given time.
 * @param integer $min_level
 *   Used to constrain events by level. Events with levels lower than this value
 *   will be ignored.
 * @param string $rule_id
 *   Regular expression for constraining results by rule ID. This will be used
 *   in a call to preg_match, but should not include the enclosing '/' tokens.
 * @param string $location_pattern
 *   String used for constraining results by location. This will be used in a
 *   call to strpos, and may contain an initial '!' signifying negation. If
 *   present, the '!' will be stripped and not used in the call to strpos, but
 *   the results of the call will be negated.
 * @param string $str_pattern
 *   String used for constraining results by message. This will be used in a
 *   call to strpos, and may contain an initial '!' signifying negation. If
 *   present, the '!' will be stripped and not used in the call to strpos, but
 *   the results of the call will be negated.
 * @param string $group_pattern
 *   String used for constraining results by event group. This will be used in a
 *   call to strpos.
 * @param string $group_regex
 *   String used for constraining results by event group. This will be used in a
 *   call to preg_match.
 * @param string $srcip_pattern
 *   String used for constraining results by source IP. This will be used in a
 *   call to strpos, and may contain an initial '!' signifying negation. If
 *   present, the '!' will be stripped and not used in the call to strpos, but
 *   the results of the call will be negated.
 * @param string $user_pattern
 *   String used for constraining results by user. This will be used in a
 *   call to strpos, and may contain an initial '!' signifying negation. If
 *   present, the '!' will be stripped and not used in the call to strpos, but
 *   the results of the call will be negated.
 * @param string $log_pattern
 *   String used for constraining results by log group. This will be used in a
 *   call to strpos.
 * @param string $log_regex
 *   String used for constraining results by log group. This will be used in a
 *   call to preg_match.
 * @param array $rc_code_hash
 *   Array keyed on pattern variable name. Contains 'true' if pattern should be
 *   negated, false otherwise. Valid keys are 'srcip_pattern', 'str_pattern'
 *   'user_pattern' and 'location_pattern'.
 * @return Ossec_Alert
 */
function __os_parsealert(&$fp, $curr_time, 
                         $init_time, $final_time, $min_level,
                         $rule_id, $location_pattern, 
                         $str_pattern, $group_pattern, $group_regex,
                         $srcip_pattern, $user_pattern, 
                         $log_pattern, $log_regex, $rc_code_hash)
{
    $evt_time = 0;
    $evt_id = 0;
    $evt_level = 0;
    $evt_description = NULL;
    $evt_location = NULL;
    $evt_srcip = NULL;
    $evt_user = NULL;
    $evt_group = NULL;
    $evt_msg[0] = "";
    
    while(!feof($fp)) 
    {
        $buffer = fgets($fp, 1024);
        
        /* Getting event header */
        if(strncmp($buffer, "** Alert", 8) != 0)
        {
            continue;
        }

        
        /* Getting event time */
        $evt_time = substr($buffer, 9, 10);
        if(is_numeric($evt_time) === FALSE)
        {
            $evt_time = 0;
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


        /* Getting group information */
        $evt_group = strstr($buffer, "-");
        if($evt_group === FALSE)
        {
            /* Invalid group */
            continue;
        }
        
        
        /* Filtering based on the group */
        if($group_pattern != NULL)
        {
            if(strpos($evt_group, $group_pattern) === FALSE)
            {
                continue;
            }
        }
        else if($group_regex != NULL)
        {
            if(!preg_match($group_regex, $evt_group))
            {
                continue;
            }
        }

        /* Getting log formats */
        if($log_pattern != NULL)
        {
            if(strpos($evt_group, $log_pattern) === FALSE)
            {
                continue;
            }
        }
        else if($log_regex != NULL)
        {
            if(!preg_match($log_regex, $evt_group))
            {
                continue;
            }
        }

        

        /* Getting location */
        $buffer = fgets($fp, 1024);
        $evt_location = substr($buffer, 21);
        if($location_pattern)
        {
            if(strpos($evt_location, $location_pattern) === FALSE)
            {
                if(!$rc_code_hash{'location_pattern'})
                    continue;
            }
            else
            {
                if($rc_code_hash{'location_pattern'})
                    continue;
            }
        }


        /* Getting rule, level and description */
        $buffer = fgets($fp, 1024);
        $token = strtok($buffer, " ");
        if($token === FALSE)
        {
            continue;
        }
        
        
        /* Rule id */
        $token = strtok(" ");
        $evt_id = $token;
        if(is_numeric($evt_id) === FALSE)
        {
            continue;
        }

        /* Checking rule id */
        if($rule_id != NULL)
        {
            if(!preg_match($rule_id, $evt_id))
            {
                continue;
            }
        }
        
        
        /* Level */
        $token = strtok(" ");
        $token = strtok(" ");
        $evt_level = $token;
        $evt_level = rtrim($evt_level, ")");
        if(is_numeric($evt_level) === FALSE)
        {
            continue;
        }

        /* Checking event level */
        if($evt_level < $min_level)
        {
            continue;
        }

        /* Getting description */
        $token = strtok("'");
        $token = strtok("'");
        $evt_description = $token;


        /* srcip */
        $buffer = fgets($fp, 1024);
        $buffer = rtrim($buffer);
        $evt_srcip = substr($buffer, 8);
        
        if($srcip_pattern != NULL)
        {
            if(strpos($evt_srcip,$srcip_pattern) === FALSE)
            {
                if(!$rc_code_hash{'srcip_pattern'})
                    continue;
            }
            else
            {
                if($rc_code_hash{'srcip_pattern'})
                    continue;
            }
        }
        

        /* user */
        $buffer = fgets($fp, 1024);
        $buffer = rtrim($buffer);
        if($buffer != "User: (none)")
        {
            $evt_user = substr($buffer, 6);
            if($evt_user == "SYSTEM")
            {
                $evt_user = NULL;
            }
        }
        if($user_pattern)
        {
            if(($evt_user == NULL) || 
               (strpos($evt_user, $user_pattern) === FALSE))
            {
                if(!$rc_code_hash{'user_pattern'})
                    continue;
            }
            else
            {
                if($rc_code_hash{'user_pattern'})
                    continue;
            }
        }
                                            
        

        /* message */
        $buffer = fgets($fp, 2048);
        $msg_id = 0;
        $evt_msg[$msg_id] = NULL;
        $pattern_matched = 0;
        while(strlen($buffer) > 3)
        {
            if($buffer == "\n")
            {
                break;
            }

            if(($str_pattern != NULL) && 
               (strpos($buffer, $str_pattern) !== FALSE))
            {
                $pattern_matched = 1;
            }

            $evt_msg[$msg_id] = rtrim($buffer);
            $evt_msg[$msg_id] = ereg_replace("<", "&lt;", $evt_msg[$msg_id]);
            $evt_msg[$msg_id] = ereg_replace(">", "&gt;", $evt_msg[$msg_id]);
            $buffer = fgets($fp, 2048);
            $msg_id++;
            $evt_msg[$msg_id] = NULL;
        }

        /* Searching by pattern */
        if($str_pattern != NULL && $pattern_matched == 0 && 
           $rc_code_hash{'str_pattern'})
        {
            $evt_srcip = NULL;
            $evt_user = NULL;
            continue;
        }
        else if(!$rc_code_hash{'str_pattern'} && $pattern_matched == 1)
        {
            $evt_srcip = NULL;
            $evt_user = NULL;
            continue;
        }

        /* If we reach here, we got a full alert */

        $alert = new Ossec_Alert( );
        
        $alert->time = $evt_time;
        $alert->id = $evt_id;
        $alert->level = $evt_level;

        // TODO: Why is this being done here? Can't we just use
        // htmlspecialchars() before emitting this to the browser?
        $evt_user = ereg_replace("<", "&lt;", $evt_user);
        $evt_user = ereg_replace(">", "&gt;", $evt_user);
        $alert->user = $evt_user;

        $evt_srcip = ereg_replace("<", "&lt;", $evt_srcip);
        $evt_srcip = ereg_replace(">", "&gt;", $evt_srcip);
        $alert->srcip = $evt_srcip;

        $alert->description = $evt_description;
        $alert->location = $evt_location;
        $alert->msg = $evt_msg;

        return($alert);
    }

    return(NULL);
}

/**
 * Performs an alert search based on the given constraints and produces a set
 * of html output files documenting the search results. An array containing
 * information about the created result files is returned, and follows this
 * example format (@see os_getstoredalerts):
 *
 * <pre>
 * Array
 * (
 *     [0] =&gt; Array
 *         (
 *             [1] =&gt; 999
 *             [count] =&gt; 2345
 *             [2] =&gt; 999
 *             [3] =&gt; 347
 *             [pg] =&gt; 3
 *         )
 * 
 *     [1] =&gt; ./tmp/output-tmp.1-1000-758a29e2a3652e86d21e3850767fb97c471906e7557054.23854549.php
 *     [2] =&gt; ./tmp/output-tmp.2-1000-758a29e2a3652e86d21e3850767fb97c471906e7557054.23854549.php
 *     [3] =&gt; ./tmp/output-tmp.3-348-758a29e2a3652e86d21e3850767fb97c471906e7557054.23854549.php
 *     [4] =&gt; 
 * )
 * </pre>
 * 
 * @param array $ossec_handle
 *   Array of information representing an OSSEC installation.
 * @param string $search_id
 *   A unique search identifier used to write search results to HTML files for
 *   later display.
 * @param integer $init_time
 *   Unix timestamp used to constrain the list of retrieved alerts to those
 *   which occur AFTER the given time. Used to constrain list of files read from
 *   the filesystem and is also passed directly to __os_parsealert.
 * @param integer $final_time
 *   Unix timestamp used to constrain the list of retrieved alerts to those
 *   which occur BEFORE the given time. Used to constrain list of files read
 *   from the filesystem and is also passed directly to __os_parsealert.
 * @param integer $max_count
 *   Used to mark when an alert list should be dumped to file. One file will be
 *   created for each 'max_count' alerts, with one additional file for any
 *   left over alerts.
 * @param integer $min_level
 *   Used to constrain events by level. Events with levels lower than this value
 *   will not be returned. Passed directly to __os_parsealert.
 * @param string $rule_id
 *   Regular expression for constraining results by rule ID. This will be used
 *   in a call to preg_match, but should not include the enclosing '/' tokens.
 *   Passed directly to __os_parsealert.
 * @param string $location_pattern
 *   String used for constraining results by location. This will be used in a
 *   call to strpos, and may contain an initial '!' signifying negation. If
 *   present, the '!' will be stripped and not used in the call to strpos, but
 *   the results of the call will be negated. Passed directly to __os_parsealert.
 * @param string $str_pattern
 *   String used for constraining results by message. This will be used in a
 *   call to strpos, and may contain an initial '!' signifying negation. If
 *   present, the '!' will be stripped and not used in the call to strpos, but
 *   the results of the call will be negated. Passed directly to __os_parsealert.
 * @param string $group_pattern
 *   String used for constraining results by event group. This will be used in a
 *   call to strpos unless in contains the '|' character, in which case it will
 *   be used in a call to preg_match. Passed directly to __os_parsealert.
 * @param string $srcip_pattern
 *   String used for constraining results by source IP. This will be used in a
 *   call to strpos, and may contain an initial '!' signifying negation. If
 *   present, the '!' will be stripped and not used in the call to strpos, but
 *   the results of the call will be negated. Passed directly to __os_parsealert.
 * @param string $user_pattern
 *   String used for constraining results by user. This will be used in a
 *   call to strpos, and may contain an initial '!' signifying negation. If
 *   present, the '!' will be stripped and not used in the call to strpos, but
 *   the results of the call will be negated. Passed directly to __os_parsealert.
 * @param string $log_pattern
 *   String used for constraining results by log group. This will be used in a
 *   call to strpos unless in contains the '|' character, in which case it will
 *   be used in a call to preg_match. Passed directly to __os_parsealert.
 * @return array
 *   An array of data identifying stored search results.
 */
function os_searchalerts($ossec_handle, $search_id,
                         $init_time, $final_time, 
                         $max_count,
                         $min_level,
                         $rule_id,
                         $location_pattern,
                         $str_pattern,
                         $group_pattern,
                         $srcip_pattern,
                         $user_pattern,
                         $log_pattern)
{
    $alert_list = new Ossec_AlertList( );
    
    $file_count = 0;
    $file_list[0] = array();

    $output_count = 1;
    $output_file[0] = array();
    $output_file[1] = array();

    $curr_time = time(0);


    /* Clearing arguments */
    if($rule_id != NULL)
    {
        $rule_id = "/".$rule_id."/";
    }

    $group_regex = null;
    if(strpos($group_pattern,"|") !== FALSE)
    {
        $group_regex = "/".$group_pattern."/";
        $group_pattern = NULL;
    }

    $log_regex = null;
    if(strpos($log_pattern,"|") !== FALSE)
    {
        $log_regex = "/".$log_pattern."/";
        $log_pattern = NULL;
    }
    
    /* Setting rc code */
    if(($user_pattern != NULL) && ($user_pattern[0] == '!'))
    {
        $user_pattern = substr($user_pattern, 1);
        $rc_code_hash{'user_pattern'} = TRUE;
    }
    else
    {
        $rc_code_hash{'user_pattern'} = FALSE;
    }

    /* str */
    if(($str_pattern != NULL) && ($str_pattern[0] == '!'))
    {
        $str_pattern = substr($str_pattern, 1);
        $rc_code_hash{'str_pattern'} = FALSE;
    }
    else
    {
        $rc_code_hash{'str_pattern'} = TRUE;
    }

    /* srcip */
    if(($srcip_pattern != NULL) && ($srcip_pattern[0] == '!'))
    {
        $srcip_pattern = substr($srcip_pattern, 1);
        $rc_code_hash{'srcip_pattern'} = TRUE;
    }
    else
    {
        $rc_code_hash{'srcip_pattern'} = FALSE;
    }
    
    /* location */
    if(($location_pattern != NULL) && ($location_pattern[0] == '!'))
    {
        $location_pattern = substr($location_pattern, 1);
        $rc_code_hash{'location_pattern'} = TRUE;
    }
    else
    {
        $rc_code_hash{'location_pattern'} = FALSE;
    }
    

    /* Cleaning old entries */
    os_cleanstored(NULL);


    /* Getting first file */
    $init_loop = $init_time;
    while($init_loop <= $final_time)
    {
        $l_year_month = date('Y/M',$init_loop);
        $l_day = date('d',$init_loop);
        
        $file_list[$file_count] = "logs/alerts/".
                                  $l_year_month."/ossec-alerts-".$l_day.".log";

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

        /* Reading all the entries */
        while(1)
        {
            /* Dont get more than max count alerts per page */
            if($alert_list->size( ) >= $max_count)
            {
                $output_file[$output_count] = "./tmp/output-tmp.".
                                            $output_count."-".$alert_list->size( )."-".
                                            $search_id.".php";
                
                __os_createresults($output_file[$output_count], $alert_list); 

                $output_file[0]{$output_count} = $alert_list->size( ) -1;
                $alert_list = new Ossec_AlertList( );
                $output_count++;
                $output_file[$output_count] = NULL;
            }
            
            $alert = __os_parsealert($fp, $curr_time, $init_time, 
                                     $final_time, $min_level,
                                     $rule_id, $location_pattern,
                                     $str_pattern, $group_pattern,
                                     $group_regex,
                                     $srcip_pattern, $user_pattern,
                                     $log_pattern, $log_regex,
                                     $rc_code_hash);
            if($alert == NULL)
            {
                break;
            }

            if(! array_key_exists( 'count', $output_file[0] ) ) {
                $output_file[0]['count'] = 0;
            }

            $output_file[0]{'count'}++;

            /* Adding alert */
            $alert_list->addAlert( $alert );

        }

        /* Closing file */
        fclose($fp);

    }


    /* Creating last entry */
    $output_file[$output_count] = "./tmp/output-tmp.".
                                  $output_count."-".$alert_list->size( )."-".
                                  $search_id.".php";
    
    $output_file[0]{$output_count} = $alert_list->size( ) -1;
    $output_file[$output_count +1] = NULL;

     __os_createresults($output_file[$output_count], $alert_list);                                  

    $output_file[0]{'pg'} = $output_count;
    return($output_file);
}


/**
 * Clean out stored search result files. If a search ID is given, all result
 * files for that search ID will be unlinked. If the given search ID is NULL,
 * all temporary files older than 30 minutes will be deleted.
 *
 * @param String $search_id
 *   A randomly-generated unique search ID or NULL.
 */
function os_cleanstored($search_id = null)
{
    if($search_id != NULL)
    {
        foreach (glob("./tmp/output-tmp.*-*-".$search_id.".php") as $filename)
        {
            unlink($filename);
        }
    }
    else
    {
        foreach (glob("./tmp/*.php") as $filename)
        {
            if(filemtime($filename) < (time(0) - 1800))
            {
                unlink($filename);
            }
        }
    }
}


/**
 * Given a unique search ID, this function returns an array containing the
 * information required to retrieve the stored search data from disk. The first
 * element of the array contains meta-information, including a count of the
 * total number of alerts, a count of the total number of pages, and the total
 * number of alerts on each page. The remaining elements are the names of the
 * files in which search results are stored, one for each page. For example:
 *
 * <pre>
 * Array
 * (
 *     [0] =&gt; Array
 *         (
 *             [1] =&gt; 999
 *             [count] =&gt; 2345
 *             [2] =&gt; 999
 *             [3] =&gt; 347
 *             [pg] =&gt; 3
 *         )
 * 
 *     [1] =&gt; ./tmp/output-tmp.1-1000-758a29e2a3652e86d21e3850767fb97c471906e7557054.23854549.php
 *     [2] =&gt; ./tmp/output-tmp.2-1000-758a29e2a3652e86d21e3850767fb97c471906e7557054.23854549.php
 *     [3] =&gt; ./tmp/output-tmp.3-348-758a29e2a3652e86d21e3850767fb97c471906e7557054.23854549.php
 *     [4] =&gt; 
 * )
 * </pre>
 * 
 * @param array $ossec_handle
 *   Array of information representing an OSSEC installation.
 * @param string $search_id
 *   Unique search identifier.
 * @return array
 *   An array of data identifying stored search results.
 */
// TODO: $ossec_handle is not used here, remove it.
function os_getstoredalerts($ossec_handle, $search_id)
{
    $output_file[0] = NULL;
    $output_file[1] = NULL;
    $output_count = 1;


    /* Cleaning old entries */
    os_cleanstored(NULL);
    
    
    $filepattern = "/^\.\/tmp\/output-tmp\.(\d{1,3})-(\d{1,6})-[a-z0-9]+\.php$/";
    
    foreach (glob("./tmp/output-tmp.*-*-".$search_id.".php") as $filename) 
    {
        if(preg_match($filepattern, $filename, $regs))
        {
            $page_n = $regs[1];
            $alert_count = $regs[2] -1;
        }
        else
        {
            continue;
        }

        if($page_n >= 1 && $page_n < 512)
        {
            $output_file[$page_n] = $filename;
            $output_file[0]{$page_n} = $alert_count;
        
            $output_file[$page_n +1] = NULL;
            $output_file[0]{'count'} += $alert_count;
            
            $output_count++;
        }
    }

    $output_file[0]{'pg'} = $output_count -1;

    return($output_file);
}

/**
 * Fetch an array of alert data, possibly constrained by time and
 * count. The returned array conforms to the following example:
 * 
 * <pre>
 *     [0] =&gt; Array
 *       (
 *           [time] =&gt; 1193749950
 *           [id] =&gt; 5402
 *           [level] =&gt; 3
 *           [user] =&gt; 
 *           [srcip] =&gt; (none)
 *           [description] =&gt; Successful sudo to ROOT executed
 *           [location] =&gt; laptop-&gt;/var/log/secure
 * 
 *           [msg] =&gt; Array
 *               (
 *                   [0] =&gt; Oct 30 09:12:30 hal sudo: dave : sorry, you must have a tty to run sudo ; TTY=unknown ; PWD=/home/dave ; USER=root ; COMMAND=/usr/sbin/open_podbay_door
 *                   [1] =&gt; 
 *               )
 *
 *       )
 * </pre>
 * 
 * @param array $ossec_handle
 *   Array of information representing an OSSEC installation.
 * @param integer $init_time
 *   Unix timestamp used to constrain the list of retrieved alerts to those
 *   which occur AFTER the given time. Passed directly to __os_parsealert.
 * @param unknown_type $final_time
 *   Unix timestamp used to constrain the list of retrieved alerts to those
 *   which occur BEFORE the given time. Passed directly to __os_parsealert.
 * @param unknown_type $max_count
 *   Maximum number of events to return. This is used go generate a guess
 *   at the correct file offset needed to return the specified number of
 *   events.
 * @return Ossec_AlertList
 *   An alert list
 */
// TODO: This is always called with init_time=0, final_time=0 and max_count=30.
function os_getalerts($ossec_handle, $init_time, $final_time, $max_count)
{
    $file = NULL;
    $alert_list = new Ossec_AlertList( );
    $curr_time = time(0);
    
    
    /* Checking if agent_dir is set */
    if(!isset($ossec_handle{'dir'})||($ossec_handle{'dir'}==NULL))
    {
        $ossec_handle{'error'} = "Unable to open ossec dir: ".
                                  $ossec_handle{'dir'};
        return(NULL);
    }


    /* Getting log dir */
    $log_file = $ossec_handle{'dir'}.'/logs/alerts/alerts.log';
    

    /* Opening alert file */
    $fp = fopen($log_file, 'r');
    if($fp === false)
    {
        $ossec_handle{'error'} = "Unable to open log file: ".$log_file;
        return(NULL);
    }


    /* If times are set to zero, we monitor the last *count files. */
    if(($init_time == 0) && ($final_time == 0))
    {
        clearstatcache();
        os_cleanstored();

        
        /* Getting file size */            
        $f_size = filesize($log_file);
        
        /* Average size of every event: 300-350 */
        $f_point = $max_count * 325;
        
        
        /* If file size is large than the counter fseek to the
         * average place in the file.
         */
        if($f_size > $f_point)
        {
            $seek_place = $f_size - $f_point;
            fseek($fp, $seek_place, "SEEK_SET");
        }
    }
    

    /* Getting alerts */
    while(1) {

        $alert = __os_parsealert(
            $fp, $curr_time, $init_time, $final_time, 0, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
        );

        if($alert == NULL) {
            break;
        }

        $alert_list->addAlert( $alert );

    }    

    fclose($fp);
    return($alert_list);
}


?>
