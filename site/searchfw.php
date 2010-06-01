<?php
/* @(#) $Id: searchfw.php,v 1.6 2008/03/03 19:37:26 dcid Exp $ */

/* Copyright (C) 2006-2008 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */
       
//TODO: Needs to be updated like search.php

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
    exit(1);
}


/* Initializing some variables */
$u_final_time = time(0);
$u_init_time = $u_final_time - $ossec_search_time;
$u_srcport = "";
$u_dstport = "";
$u_action = "";
$u_srcip = "";
$u_dstip = "";
$u_location = "";

$USER_srcip = NULL;
$USER_dstip = NULL;
$USER_srcport = NULL;
$USER_dstport = NULL;
$USER_action = NULL;
$USER_location = NULL;
$USER_protocol = NULL;


/* Reading user input -- being very careful parsing it */
$datepattern = "/^([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2})$/";
if(isset($_POST['initdate']))
{             
    if(preg_match($datepattern, $_POST['initdate'], $regs))
    {
        $USER_init = mktime($regs[4], $regs[5], 0,$regs[2],$regs[3],$regs[1]);
        $u_init_time = $USER_init;
    }
}
if(isset($_POST['finaldate']))
{             
    if(preg_match($datepattern, $_POST['finaldate'], $regs) == true)
    {
        $USER_final = mktime($regs[4], $regs[5], 0,$regs[2],$regs[3],$regs[1]);
        $u_final_time = $USER_final;
    }
}

/* Getting ports */
if(isset($_POST['srcport']))
{             
    if((is_numeric($_POST['srcport'])) && 
        ($_POST['srcport'] >= 0) &&
        ($_POST['srcport'] < 65536))
    {
        $USER_srcport = $_POST['srcport'];
        $u_srcport = $USER_srcport;
    }
}

if(isset($_POST['dstport']))
{             
    if((is_numeric($_POST['dstport'])) && 
        ($_POST['dstport'] >= 0) &&
        ($_POST['dstport'] < 65536))
    {
        $USER_dstport = $_POST['dstport'];
        $u_dstport = $USER_dstport;
    }
}


/* Getting location */
if(isset($_POST['locationpattern']))
{
    $lcpattern = "/^[0-9a-zA-Z. _|^!>\/\\-]{1,156}$/";    
    if(preg_match($lcpattern, $_POST['locationpattern']) == true)
    {
        $USER_location = $_POST['locationpattern'];
        $u_location = $USER_location;
    }
}


/* Src ip pattern */
if(isset($_POST['srcippattern']))
{
   if(preg_match($strpattern, $_POST['srcippattern']) == true)
   {
       $USER_srcip = $_POST['srcippattern'];
       $u_srcip = $USER_srcip;
   }
}

/* dst ip */
if(isset($_POST['dstippattern']))
{
    if(preg_match($strpattern, $_POST['dstippattern']) == true)
    {
        $USER_dstip = $_POST['dstippattern'];
        $u_dstip = $USER_dstip;
    }
}

/* User pattern */
if(isset($_POST['action']))
{
   if(preg_match($strpattern, $_POST['action']) == true)
   {
       $USER_action = $_POST['action'];
       $u_action = $USER_action;
   }
}


/* Maximum number of alerts */
if(isset($_POST['max_alerts_per_page']))
{
    if(preg_match($intpattern, $_POST['max_alerts_per_page']) == true)
    {
        if(($_POST['max_alerts_per_page'] > 0) &&
           ($_POST['max_alerts_per_page'] < 200000))
        {
            $ossec_max_alerts_per_page = $_POST['max_alerts_per_page'];
        }
    }
}    


echo "<h1>Firewall search options:</h1>\n";

/* Search forms */
echo '
<table><tr valign="top">
<form name="dosearch" method="post" action="index.php?f=sf">
    <td>From: </td><td><input type="text" name="initdate" 
    id="i_date_a" size="17"
    value="'.date('Y-m-d H:i', $u_init_time).'" maxlength="16" 
    class="formText" />
    <img src="img/calendar.gif" id="i_trigger" title="Date selector" 
    class="formText" />
    </td><td>
    To: </td><td><input type="text" name="finaldate" id="f_date_a" size="17"
    value="'.date('Y-m-d H:i', $u_final_time).'" maxlength="16" 
    class="formText" />
    <img src="img/calendar.gif" id="f_trigger" title="Date selector" 
    class="formText" />
    </td>
    </tr>
';


/* Srcip pattern */
echo '<tr><td>    
    Srcip: </td><td>
    <input type="text" name="srcippattern" size="16" class="formText" 
                    value="'.$u_srcip.'"/>&nbsp;&nbsp;';

/* Dst pattern */
echo '</td><td>
    Dstip: </td><td><input type="text" name="dstippattern" size="8" 
                    value="'.$u_dstip.'" class="formText" /></td></tr>';
                    
/* Srcport pattern */
echo '<tr><td>    
    Src port: </td><td>
    <input type="text" name="srcportpattern" size="16" class="formText" 
                    value="'.$u_srcport.'"/>&nbsp;&nbsp;';

/* Dstport pattern */
echo '</td><td>
    Dst port: </td><td><input type="text" name="dstportpattern" size="8" 
                    value="'.$u_dstport.'" class="formText" /></td></tr>';

/* Location */
echo '<tr><td>    
    Location: </td><td>
    <input type="text" name="locationpattern" size="16" class="formText" 
                    value="'.$u_location.'"/>&nbsp;&nbsp;';

/* Action  */
echo '</td><td>
    Action:</td>
    <td><input type="text" name="actionpattern" size="16"
    value="'.$u_action.'" class="formText" /></td></tr>';
    
    
/* Max Alerts  */
echo '</tr><td>
    Max Alerts:</td>
    <td><input type="text" name="max_alerts_per_page" size="8"
    value="'.$ossec_max_alerts_per_page.'" class="formText" /></td></tr>';

    
/* Final form */
echo '
    <tr><td>                    
    <input type="submit" name="search" value="Search" class="button"
           class="formText" />
    </form>
';


echo "</td></tr></table><br /> <br />\n";


/* Java script for date */
echo '
<script type="text/javascript">
Calendar.setup({
button          :   "i_trigger", 
inputField     :    "i_date_a",
ifFormat       :    "%Y-%m-%d %H:%M",
showsTime      :    true,
timeFormat     :    "24"
});
Calendar.setup({
button          :   "f_trigger", 
inputField     :    "f_date_a",
ifFormat       :    "%Y-%m-%d %H:%M",
showsTime      :    true,
timeFormat     :    "24"
});
</script>

';

echo "<h1>Results:</h1>\n";

if(!isset($USER_init) || !isset($USER_final))
{
    echo "<b>No search performed.</b><br />\n";
    return(1);
}

/* Search id not used */
$search_id = NULL;

/* Getting last firewall events */
$alert_list = os_searchfw($ossec_handle, $search_id,
                          $USER_init, $USER_final, 
                          $ossec_max_alerts_per_page,
                          $USER_protocol,
                          $USER_srcip, $USER_dstip,
                          $USER_srcport, $USER_dstport,
                          $USER_action, $USER_location);
if($alert_list == NULL)
{
    echo "<b class='red'>Nothing returned. </b><br />\n";
}
else
{
    echo "<b>Total entries found: </b>".sizeof($alert_list)."<br /><br />";

    /* Printing all available dstips  */
    echo '<table width="100%">';
    search_pavailable($alert_list[0]{'dstips'}, 
                      $alert_list[0]{'dstips_total'}, 
                      "dstip", "Destination IP", "Dst IP breakdown");
    
    /* Printing all available srcips */
    search_pavailable($alert_list[0]{'srcips'}, 
                      $alert_list[0]{'srcips_total'}, 
                      "srcip", "Source IP", "Src IP breakdown");


    echo '</table><br />';
}


/* Printing all rules */
$evt_count = sizeof($alert_list) -1;
if($evt_count >= ($ossec_max_alerts_per_page -3))
{
    echo '
        <script type="text/javascript">
        alert (\'Your search returned more than the maximum value allowed: "'.
        $ossec_max_alerts_per_page.'". Please narrow your search to '. 
        'see all events.\')
        </script>';
}


/* Initializing div closeout control */
$dstip_div = 0;
$srcip_div = 0;


echo '<h2>Alert list</h2>';


while($evt_count > 0)
{
    $alert = $alert_list[$evt_count];
    $al_date = date('Y M d H:i:s', $alert{'time'});
    
    /* Printing dstip block */
    if(isset($alert{'dstip_count'}))
    {
        if($dstip_div == 1)
        {
            /* We also close the srcip div */
            echo '</div></div>';
            $srcip_div = 0;
        }
        else
        {
            $dstip_div = 1;
        }
        echo '<div id="ctdstip'.$alert{'dstip'}.'-'.$alert{'dstip_count'}.'" 
            style="display: block">';
    }
    

    /* Printing srcip block */
    if(isset($alert{'srcip_count'}))
    {
        if($srcip_div == 1)
        {
            echo '</div>';
        }
        else
        {
            $srcip_div = 1;
        }

        echo '<div id=\'ctsrcip'.$alert{'srcip'}.'-'.$alert{'srcip_count'}.'\'
            style="display: block">';
    }

    echo "<div class=\"alert\"><b>".$al_date
        .'</b> Firewall <strong>'.$alert{'action'}."</strong>\n<br />";
    echo "<b>Location: </b>".$alert{'location'};    
    echo
        '</div><div class="msg">'."\n";

    echo $alert{'msg'}."<br />\n";     
    echo "<br /></div>\n";
    $evt_count--;
}

/* Closing out left divs */
if($srcip_div == 1)
{
    echo "</div>";
}
if($dstip_div == 1)
{
    echo "</div>";
}

/* EOF */
?>
