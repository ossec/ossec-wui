<?php
/* @(#) $Id: syscheck.php,v 1.6 2008/03/03 19:37:26 dcid Exp $ */

/* Copyright (C) 2006-2008 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */
       

/* Initializing variables */
$u_agent = "ossec-server";
$u_file = "";
$USER_agent = NULL;
$USER_file = NULL;


/* Getting user patterns */
$strpattern = "/^[0-9a-zA-Z._^ -]{1,128}$/";
if(isset($_POST['agentpattern']))
{
    if(preg_match($strpattern, $_POST['agentpattern']) == true)
    {
        $USER_agent = $_POST['agentpattern'];
        $u_agent = $USER_agent;
    }
}
if(isset($_POST['filepattern']))
{
    if(preg_match($strpattern, $_POST['filepattern']) == true)
    {
        $USER_file = $_POST['filepattern'];
        $u_file = $USER_file;
    }
}      


/* OS PHP init */
if (!function_exists('os_handle_start'))
{
    echo "<b class='red'>You are not allowed direct access.</b><br />\n";
    return(1);
}


/* Starting handle */
$ossec_handle = os_handle_start($ossec_dir);
if($ossec_handle == NULL)
{
    echo "Unable to access ossec directory.\n";
    return(1);
}


/* Getting syscheck information */
$syscheck_list = os_getsyscheck($ossec_handle);


/* Creating form */
echo '
<form name="dosearch" method="post" action="index.php?f=i">
<table><tr valign="top">
<td>
Agent name: </td><td><select name="agentpattern" class="formText">';

foreach($syscheck_list as $agent => $agent_name)
{
    $sl = "";
    if($agent == "global_list")
    {
        continue;
    }
    else if($u_agent == $agent)
    {
        $sl = ' selected="selected"';
    }
    echo '<option value="'.$agent.'" '.$sl.
         '> &nbsp; '.$agent.'</option>
         ';
}

echo '</select></td>';

echo '     
    <td><input type="submit" name="ss" value="Dump database" class="button"/>';

if($USER_agent != NULL)
{
    echo ' &nbsp; &nbsp;<a class="bluez" href="index.php?f=i"> &lt;&lt;back</a>';
}

echo '           
    </td>
    </tr></table>
    </form>
    ';          

      
/* Dumping database */
if( array_key_exists( 'ss', $_POST ) ) {
    if(($_POST['ss'] == "Dump database") && ($USER_agent != NULL))
    {
        os_syscheck_dumpdb($ossec_handle, $USER_agent);
        return(1);
    }
}

/* Last modified files */
echo "<br /><h2>Latest modified files (for all agents): </h2>\n\n";
if(($syscheck_list == NULL) || ($syscheck_list{'global_list'} == NULL))
{
    echo '<ul class="ulsmall bluez">
        No integrity checking information available.<br />
        Nothing reported as changed.
        </ul>
      ';
}
else
{

   echo '<table><tr><td valign="top">';
   if(isset($syscheck_list{'global_list'}) && 
      isset($syscheck_list{'global_list'}{'files'}))
   {
       $last_mod_date = "";
       $sk_count = 0;
       
       foreach($syscheck_list{'global_list'}{'files'} as $syscheck)
       {
           $sk_count++;
           
           # Initing file name
           $ffile_name = "";
           $ffile_name2 = "";
           
           if(strlen($syscheck[2]) > 90)
           {
               $ffile_name = substr($syscheck[2], 0, 95)."..";
               $ffile_name2 = substr($syscheck[2], 96, 160);
           }
           else
           {
               $ffile_name = $syscheck[2];
           }
           
           /* Setting the date */
           if($last_mod_date != date('Y M d', $syscheck[0]))
           {
               $last_mod_date = date('Y M d', $syscheck[0]);
               echo "\n<br /><b>$last_mod_date</b><br />\n";
           }
           
           echo '
               <span id="togglesk'.$sk_count.'">
               <a  href="#" class="bluez" title="Expand '.$syscheck[2].'" 
               onclick="ShowSection(\'sk'.$sk_count.'\');return false;">+'.
               $ffile_name.'</a><br /> 
               </span>

               <div id="contentsk'.$sk_count.'" style="display: none">

               <a  href="#" title="Hide '.$syscheck[2].'" 
               onclick="HideSection(\'sk'.
               $sk_count.'\');return false;">-'.$ffile_name.'</a>
               <br />
               <div class="smaller">
               &nbsp;&nbsp;<b>File:</b> '.$ffile_name.'<br />';
               if($ffile_name2 != "")
               {
                   echo "&nbsp;&nbsp;&nbsp;&nbsp;".$ffile_name2.'<br />';
               }
               echo '
               &nbsp;&nbsp;<b>Agent:</b> '.$syscheck[1].'<br />
               &nbsp;&nbsp;<b>Modification time:</b> '.
               date('Y M d H:i:s', $syscheck[0]).'<br />
               </div>

               </div>
               ';
       }
   }
}


echo "</td></tr></table>
      <br /> <br />\n";


?>
