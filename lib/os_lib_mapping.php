<?php
/* @(#) $Id: os_lib_mapping.php,v 1.7 2008/03/03 19:37:25 dcid Exp $ */

/* Copyright (C) 2006-2008 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

/**
 * This file contains utility functions for fetching user mappings.
 * 
 * @copyright Copyright (c) 2006-2008, Daniel B. Cid, All rights reserved.
 * @package ossec_web_ui
 * @author  Daniel B. Cid <dcid@ossec.net>
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GNU Public License
 * 
 */

/**
 * Fetch user mapping from the FTS queue.
 *
 * @param unknown_type $ossec_handle
 * @return unknown
 */
function os_getusermapping($ossec_handle)
{
    $fp = NULL;
    $file = NULL;
    $mapping_list;

    $fp = fopen($ossec_handle{'dir'}."/queue/fts/fts-queue", "r");
    if($fp === FALSE)
    {
        return(NULL);
    }

    $fts_list = array("sshd", "windows");
    $ign_users = array("SYSTEM");
    
    $preg_fts = "/^(\\S+)\\s+(\\S+)\\s+(\\S+.+)$/";
    
    
    while(!feof($fp))
    {
        $buffer = fgets($fp, 1024);
        $buffer = rtrim($buffer);

        foreach($fts_list as $fts)
        {
            if(strncmp($buffer, $fts, strlen($fts)) == 0)
            {
                if(preg_match($preg_fts, $buffer, $regs) !== FALSE)
                {
                    $ign = 0;
                    foreach($ign_users as $ign)
                    {
                        if($regs[2] == $ign)
                        {
                            $ign = 1;
                        }
                    }
                    if($ign == 0)
                    {
                        $location = NULL;
                        $u_info{'proto'} = $regs[1];
                        $u_info{'user'} = $regs[2];
                        if(strchr($regs[3], ">") === FALSE)
                        {
                            $location = "ossec-server->".$regs[3];
                        }
                        else
                        {
                            $location = $regs[3];
                        }
                        $mapping_list{$location}[] = $u_info;
                    }
                }
                break;
            }
        }
    }

    fclose($fp);
    
    return($mapping_list);
}


?>
