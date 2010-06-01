<?php
/* @(#) $Id: stats.php,v 1.9 2008/03/03 19:37:26 dcid Exp $ */

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


/* Current date values */
$curr_time = time(0);
$curr_day = date('d',$curr_time);
$curr_month = date('m', $curr_time);
$curr_year = date('Y', $curr_time);


/* Getting user values */
if(isset($_POST['day']))
{
    if(is_numeric($_POST['day']))
    {
        if(($_POST['day'] >= 0) && ($_POST['day'] <= 31))
        {
            $USER_day = $_POST['day'];
        }
    }
}
if(isset($_POST['month']))
{
    if(is_numeric($_POST['month']))
    {
        if(($_POST['month'] > 0) && ($_POST['month'] <= 12))
        {
            $USER_month = $_POST['month'];
        }
    }
}
if(isset($_POST['year']))
{
    if(is_numeric($_POST['year']))
    {
        if(($_POST['year'] >= 1) && ($_POST['year'] <= 3000))
        {
            $USER_year = $_POST['year'];
        }
    }
}


/* Building stat times */
if(isset($USER_year) && isset($USER_month) && isset($USER_day))
{
    /* Stat for whole month */
    if($USER_day == 0)
    {
        $init_time = mktime(0, 0, 0, $USER_month, 1, $USER_year);
        $final_time = mktime(0, 0, 0, $USER_month +1, 0, $USER_year);
    }

    else
    {
        $init_time = mktime(0, 0, 0, $USER_month, $USER_day, $USER_year);
        $final_time = mktime(0, 0, 10, $USER_month, $USER_day, $USER_year);
        
        /* Getting valid formated day */
        $USER_day = date('d',$init_time);
    }
}
else
{
    $init_time = $curr_time -1;
    $final_time = $curr_time;

    /* Setting user values */
    $USER_month = $curr_month;
    $USER_day = $curr_day;
    $USER_year = $curr_year;
}




/* Day option */
echo "<h2>Stats options:</h2><br />\n";
echo '

<form name="dosearch" method="post" action="index.php?f=t">

Day:  <select name="day" class="formSelect">
    <option value="0">All days</option>
';
for($l_counter = 1; $l_counter <= 31 ; $l_counter++)
{
    $tmp_msg = '';
    if($l_counter == $USER_day)
    {
        $tmp_msg = ' selected="selected"';
    }
    echo '   <option value="'.$l_counter.'"'.$tmp_msg.'>'.
         $l_counter.'</option>';
}
echo '  </select>';


/* Monthly */
echo ' Month: <select name="month" class="formSelect">
    ';
$months = array("January" => "Jan", 
                "February" => "Feb", 
                "March" => "Mar", 
                "April" => "Apr", 
                "May" => "May",
                "June" => "Jun",
                "July" => "Jul", 
                "August" => "Aug", 
                "September" => "Sep", 
                "October" => "Oct", 
                "November" => "Nov", 
                "December" => "Dec");
$mnt_ct = 1;
foreach($months as $tmp_month => $tmp_month_v)
{
    if($USER_month == $mnt_ct)
    {
        echo '    <option value="'.$mnt_ct.'" selected="selected">'.
             $tmp_month.'</option>';
    }
    else
    {
        echo '    <option value="'.$mnt_ct.'">'.$tmp_month.'</option>';
    }
    $mnt_ct++;
}
echo '  </select>';


/* Year */
echo ' Year: <select name="year" class="formSelect">
    <option value="'.$curr_year.'" selected="selected">'.$curr_year.'</option>
    <option value="'.($curr_year-1).'">'.($curr_year-1).'</option>
    <option value="'.($curr_year-2).'">'.($curr_year-2).'</option>
    ';
echo '  </select> <input type="submit" name="Stats" value="Change options" class="button" /></form>';



/* Getting daily stats */
$l_year_month = date('Y/M', $init_time);

$stats_list = os_getstats($ossec_handle, $init_time, $final_time);

$daily_stats = array();
if(isset($stats_list{$l_year_month}{$USER_day}))
{
    $daily_stats = $stats_list{$l_year_month}{$USER_day};
    $all_stats = $stats_list{$l_year_month};
}

if(!isset($daily_stats{'total'}))
{
    echo '<br />
        <b class="red">No stats available.</b>';
    return(1);
}
else
{
    echo '<br />';
}
        

/* Day 0 == month stats */
if($USER_day == 0)
{
    echo "<h2>Ossec Stats for: <b id='blue'>".$l_year_month."</b></h2><br />\n";
}
else
{
    echo "<h2>Ossec Stats for: <b id='blue'>".$l_year_month.
         "/".$USER_day."</b> </h2><br /><br />\n\n";
}

echo '<b>Total</b>: '.number_format($daily_stats{'total'}).'<br />';
echo '<b>Alerts</b>: '.number_format($daily_stats{'alerts'}).'<br />';
echo '<b>Syscheck</b>: '.number_format($daily_stats{'syscheck'}).'<br />';
echo '<b>Firewall</b>: '.number_format($daily_stats{'firewall'}).'<br />';
if($USER_day != 0)
{
    (int)$h_avg = (int)$daily_stats{'total'}/24;
    echo '<b>Average</b>: '.sprintf("%.01f", $h_avg).' events per hour.';
}

echo '<br /><br />';
echo '<br /><div class="statssmall">';
echo '
<table align="center"><tr valign="top"><td width="50%">

<table summary="Total values">
    <caption><strong>Aggregate values by severity</strong></caption>
    <tr>
    <th>Option</th>
    <th>Value</th>
    <th>Percentage</th>
    </tr>
';

if( array_key_exists( 'level', $daily_stats ) ) {
    asort($daily_stats{'level'});
}

if( array_key_exists( 'rule', $daily_stats ) ) {
    asort($daily_stats{'rule'});
}

$odd_count = 0;
$odd_msg = '';

if( array_key_exists( 'level', $daily_stats ) ) {
	foreach($daily_stats{'level'} as $l_level => $v_level)
	{
	    (int)$level_pct = (int)($v_level * 100)/$daily_stats{'alerts'};
	    if(($odd_count % 2) == 0)
	    {
	        $odd_msg = ' class="odd"';
	    }
	    else
	    {
	        $odd_msg = '';
	    }
	    $odd_count++;
	    echo '
	    <tr'.$odd_msg.'>
	    <td>Total for level '.$l_level.'</td>
	    <td>'.number_format($v_level).'</td>
	    <td>'.sprintf("%.01f", $level_pct).'%</td>
	    </tr>
	    ';
	}
}
if(($odd_count % 2) == 0)
{
    $odd_msg = ' class="odd"';
}
else
{
    $odd_msg = '';
}
echo '
<tr'.$odd_msg.'>
<td>Total for all levels</td>
<td>'.number_format($daily_stats{'alerts'}).'</td>
<td>100%</td>
</tr>
</table>

</td>

<td width="50%">
<table summary="Total values">
    <caption><strong>Aggregate values by rule</strong></caption>
    <tr>
    <th>Option</th>
    <th>Value</th>
    <th>Percentage</th>
    </tr>
';


$odd_count = 0;
$odd_msg = '';

if( array_key_exists( 'rule', $daily_stats ) ) {
	foreach($daily_stats{'rule'} as $l_rule => $v_rule)
	{
	    (int)$rule_pct = (int)($v_rule * 100)/$daily_stats{'alerts'};
	    if(($odd_count % 2) == 0)
	    {
	        $odd_msg = ' class="odd"';
	    }
	    else
	    {
	        $odd_msg = '';
	    }
	    $odd_count++;
	    echo '
	    <tr'.$odd_msg.'>
	    <td>Total for Rule '.$l_rule.'</td>
	    <td>'.number_format($v_rule).'</td>
	    <td>'.sprintf("%.01f", $rule_pct).'%</td>
	    </tr>
	    ';
	}
}
if(($odd_count % 2) == 0)
{
    $odd_msg = ' class="odd"';
}
else
{
    $odd_msg = '';
}
echo '
<tr'.$odd_msg.'>
<td>Total for all rules</td>
<td>'.number_format($daily_stats{'alerts'}).'</td>
<td>100%</td>
</tr>
';

echo '
</table>
</td></tr></table>
';


/* Monthly stats */
if($USER_day == 0)
{
echo '

        <br /><br />
        <table align="center" summary="Total by day">
        <caption><strong>Total values per Day</strong></caption>
        <tr>
        <th>Day</th>
        <th>Alerts</th>
        <th>Alerts %</th>
        <th>Syscheck</th>
        <th>Syscheck %</th>
        <th>Firewall</th>
        <th>Firewall %</th>
        <th>Total</th>
        <th>Total %</th>
        </tr>
        ';

    $odd_count = 0;
    $odd_msg;
    for($i = 1; $i<=31; $i++)
    {
        if($i < 10)
        {
            $myi = "0$i";
        }
        else
        {
            $myi = $i;
        }
            
        if(!isset($all_stats{$myi}{'total'}))
        {
            continue;
        }
        
        $d_total = $all_stats{$myi}{'total'};
        $d_alerts = $all_stats{$myi}{'alerts'};
        $d_syscheck = $all_stats{$myi}{'syscheck'};
        $d_firewall = $all_stats{$myi}{'firewall'};


        (int)$total_pct = (int)($d_total * 100)/max($daily_stats{'total'},1);
        (int)$alerts_pct = (int)($d_alerts * 100)/max($daily_stats{'alerts'},1);
        (int)$syscheck_pct=(int)($d_syscheck *100)/max($daily_stats{'syscheck'},1);
        (int)$firewall_pct=(int)($d_firewall *100)/max($daily_stats{'firewall'},1);

        if(($odd_count % 2) == 0)
        {
            $odd_msg = ' class="odd"';
        }
        else
        {
            $odd_msg = '';
        }
        $odd_count++;
        echo '
            <tr'.$odd_msg.'>
            <td>Day '.$i.'</td>
            <td>'.number_format($d_alerts).'</td>
            <td>'.sprintf("%.01f", $alerts_pct).'%</td>

            <td>'.number_format($d_syscheck).'</td>
            <td>'.sprintf("%.01f", $syscheck_pct).'%</td>

            <td>'.number_format($d_firewall).'</td>
            <td>'.sprintf("%.01f", $firewall_pct).'%</td>

            <td>'.number_format($d_total).'</td>
            <td>'.sprintf("%.01f", $total_pct).'%</td>
            </tr>
            ';
    }
}

/* Daily stats */
else
{
    echo '

        <br /><br />
        <table align="center" summary="Total by hour">
        <caption><strong>Total values per hour</strong></caption>
        <tr>
        <th>Hour</th>
        <th>Alerts</th>
        <th>Alerts %</th>
        <th>Syscheck</th>
        <th>Syscheck %</th>
        <th>Firewall</th>
        <th>Firewall %</th>
        <th>Total</th>
        <th>Total %</th>
        </tr>
        ';

    $odd_count = 0;
    $odd_msg;
    for($i = 0; $i<=23; $i++)
    {
        if(!isset($daily_stats{'total_by_hour'}[$i]))
        {
            continue;
        }

        $hour_total = $daily_stats{'total_by_hour'}[$i];
        $hour_alerts = $daily_stats{'alerts_by_hour'}[$i];
        $hour_syscheck = $daily_stats{'syscheck_by_hour'}[$i];
        $hour_firewall = $daily_stats{'firewall_by_hour'}[$i];

        (int)$total_pct = (int)($hour_total * 100)/max($daily_stats{'total'},1);
        (int)$alerts_pct = (int)($hour_alerts * 100)/max($daily_stats{'alerts'},1);
        (int)$syscheck_pct=(int)($hour_syscheck *100)/max($daily_stats{'syscheck'},1);
        (int)$firewall_pct=(int)($hour_firewall *100)/max($daily_stats{'firewall'},1);

        if(($odd_count % 2) == 0)
        {
            $odd_msg = ' class="odd"';
        }
        else
        {
            $odd_msg = '';
        }
        $odd_count++;
        echo '
            <tr'.$odd_msg.'>
            <td>Hour '.$i.'</td>
            <td>'.number_format($hour_alerts).'</td>
            <td>'.sprintf("%.01f", $alerts_pct).'%</td>

            <td>'.number_format($hour_syscheck).'</td>
            <td>'.sprintf("%.01f", $syscheck_pct).'%</td>

            <td>'.number_format($hour_firewall).'</td>
            <td>'.sprintf("%.01f", $firewall_pct).'%</td>

            <td>'.number_format($hour_total).'</td>
            <td>'.sprintf("%.01f", $total_pct).'%</td>
            </tr>
            ';
    }
}

echo '
</table></div>
';


?>
