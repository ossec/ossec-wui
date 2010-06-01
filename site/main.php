<?php
/* @(#) $Id: main.php,v 1.12 2008/03/03 19:37:26 dcid Exp $ */

/* Copyright (C) 2006-2008 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */
       


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


/* Getting all agents */
if(($agent_list = os_getagents($ossec_handle)) == NULL)
{
    echo "No agent available.\n";
    return(1);
}


/* Printing current date */
echo '<div class="smaller2">'.date('F dS Y h:i:s A').'</div><br />';


/* Getting syscheck information */
$syscheck_list = os_getsyscheck($ossec_handle);

echo '<table width="95%"><tr><td width="45%" valign="top">';


/* Available agents */
echo "<h2>Available&nbsp;agents:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</h2><br />\n\n";


/* Agent count for java script */
$agent_count = 0;


/* Looping all agents */
foreach ($agent_list as $agent) 
{
    $atitle = "";
    $aclass = "";
    $amsg = "";

    /* If agent is connected */
    if($agent{'connected'})
    {
        $atitle = "Agent active";
        $aclass = 'class="bluez"';
    }
    else
    {
        $atitle = "Agent Inactive";
        $aclass = 'class="red"';
        $amsg = " - Inactive";
    }

    echo '
        <span id="toggleagt'.$agent_count.'">
        <a  href="#" '.$aclass.' title="'.$atitle.'" 
        onclick="ShowSection(\'agt'.$agent_count.'\');return false;">+'.
        $agent{'name'}." (".$agent{'ip'}.')'.$amsg.'</a><br /> 
        </span>

        <div id="contentagt'.$agent_count.'" style="display: none">

        <a  href="#" '.$aclass.' title="'.$atitle.'" 
        onclick="HideSection(\'agt'.
        $agent_count.'\');return false;">-'.$agent{'name'}.
        " (".$agent{'ip'}.')'.$amsg.'</a>
        <br />
        <div class="smaller">
        &nbsp;&nbsp;<b>Name:</b> '.$agent{'name'}.'<br />
        &nbsp;&nbsp;<b>IP:</b> '.$agent{'ip'}.'<br />
        &nbsp;&nbsp;<b>Last keep alive:</b> '.
        date('Y M d H:i:s', $agent{'change_time'}).'<br />
        &nbsp;&nbsp;<b>OS:</b> '.$agent{'os'}.'<br />
        </div>
        </div>
        ';
    echo "\n";
    $agent_count++;
}

echo '</td>';


/* Last modified files */
echo "<td valign='top' width='55%'><h2>Latest modified files: </h2><br />\n\n";
$syscheck_list = os_getsyscheck($ossec_handle);
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
   if(isset($syscheck_list{'global_list'}) && 
      isset($syscheck_list{'global_list'}{'files'}))
   {
       $sk_count = 0;
       
       foreach($syscheck_list{'global_list'}{'files'} as $syscheck)
       {
           $sk_count++;
           if($sk_count > ($agent_count +4))
           {
               break;
           }
           
           # Initing file name
           $ffile_name = "";
           $ffile_name2 = "";
           
           if(strlen($syscheck[2]) > 40)
           {
               $ffile_name = substr($syscheck[2], 0, 45)."..";
               $ffile_name2 = substr($syscheck[2], 46, 85);
           }
           else
           {
               $ffile_name = $syscheck[2];
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


echo '</td></tr></table>
';
echo "<br /> <br />\n";


/* Getting last alerts */
$alert_list = os_getalerts($ossec_handle, 0, 0, 30);
if($alert_list == NULL)
{
    echo "<b class='red'>Unable to retrieve alerts. </b><br />\n";
}
else
{
    echo "<h2>Latest events</h2><br />\n";
    $alert_count = $alert_list->size() -1;
    $alert_array = $alert_list->alerts();

    while($alert_count >= 0)
    {
        echo $alert_array[$alert_count]->toHtml();
        $alert_count--;
    }
}

?>
