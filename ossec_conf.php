<?php

/* OSSEC Configuration for the UI. Make sure to set
 * right ossec_dir in here. If your server does not
 * have much memory available, reduce the max_alerts
 * variable to something smaller.
 */

/* Ossec directory */
$ossec_dir="/var/ossec";


/* Maximum alerts per page */
$ossec_max_alerts_per_page = 1000;


/* Default search values */
$ossec_search_level = 7;
$ossec_search_time = 14400;


/* Default refreshing time */
$ossec_refresh_time = 90;

?>
