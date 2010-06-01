<?php
/* @(#) $Id: user_mapping.php,v 1.6 2008/03/03 19:37:26 dcid Exp $ */

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
    echo "<b class='red'>Unable to access ossec directory.</b><br />\n";
    return(1);
}


if(($mapping_list = os_getusermapping($ossec_handle)) == NULL)
{
    echo "<b class='red'>No user mapping available. </b><br />\n";
    return(1);
}


/* Available agents */
echo "<h1>User mapping by system: </h1>\n\n";
$int_count = 0;
foreach($mapping_list as $key => $system)
{
    echo '<a href="#'.$int_count.'" id="blue">'.$key.'</a><br />'."\n";
    $int_count++;
}

echo '<table width="50%">';

$int_count = 0;
foreach($mapping_list as $key => $system)
{
    $close_tag = "";
    echo '<a name="'.$int_count.'"></a>'."\n";
    
    if(($int_count == 0) || (($int_count % 2) == 0))
    {
        echo '<tr valign="top"><td><h2>'.$key.'</h2>';
        
        $close_tag = '</td>';
    }
    else
    {
        echo '<td align="top"><h2>'.$key.'</h2>';
        $close_tag = "</td></tr>";
    }

    foreach($system as $user_list)
    {
        echo $user_list{'proto'}.": ".$user_list{'user'}."<br />\n";
    }
    
    echo $close_tag;
    $int_count++;
}

/* Need to close tr in odd numbers */
if(($int_count != 0) && (($int_count % 2) != 0))
{
    echo '</tr>';
}

echo '</table>';
echo "<br /> <br />\n";


?>
