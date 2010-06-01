<?php


/* Update the include path so that all library files can be
 * easily found.
 */
ini_set('include_path', ini_get('include_path').':'.dirname(__FILE__).'/lib');


/* Getting user argument (page) */
$USER_f = false;
if(isset($_GET['f']))
{
	$USER_f = $_GET['f'];
}
/* If nothing is set, default to the main page. */
else
{
	$USER_f = "m";
}
?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
	<head>
		<title>OSSEC Web Interface - Open Source Security</title>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
		<meta name="author" content="Daniel B. Cid - ossec.net" />
		<meta name="copyright" content="2006-2008 by Daniel B. Cid ossec.net" />
		<meta name="keywords" content="ids, ossec, hids, free software" />
		<meta name="description" content="OSSEC Web Interface" />
        <?php
        
        /* If we are in the main page, refresh the results every 90 seconds.*/
        if($USER_f == "m")
        {
            echo '<meta http-equiv="refresh" content="90" />';
        }
        ?>
        <link rel="shortcut icon" href="css/images/favicon.ico" />
        <link rel="stylesheet" type="text/css" media="all" 
              href="css/cal.css" title="css/cal.css" />
        <script type="text/javascript" src="js/calendar.js"></script>
        <script type="text/javascript" src="js/calendar-en.js"></script>
        <script type="text/javascript" src="js/calendar-setup.js"></script>
        <script type="text/javascript" src="js/prototype.js"></script>
        <script type="text/javascript" src="js/hide.js"></script>
        
        <link rel="stylesheet" rev="stylesheet"
                      href="css/css.css" type="text/css" />
	</head>
    
<body>
<br/>


<?php 
    /* Defining the error messages */
    $int_error="Internal error. Try again later.\n <br />";
    $include_error="Unable to include file:";
    
    /* Including the header */
    if(!(include("site/header.html")))
    {
        echo "$include_error 'site/header.html'.\n<br />";
        echo "$int_error<br />";
        return(1);
    }
?>

  <div id="container">
    <div id="content_box">
    <div id="content" class="pages">
    <a name="top"></a>

			<!-- BEGIN: content -->

            <?php

            $array_lib = array("ossec_conf.php", "lib/ossec_categories.php",
                          "lib/ossec_formats.php",  
                          "lib/os_lib_handle.php",
                          "lib/os_lib_agent.php",
                          "lib/os_lib_mapping.php",
                          "lib/os_lib_stats.php",
                          "lib/os_lib_syscheck.php",
                          "lib/os_lib_firewall.php",
                          "lib/os_lib_alerts.php");

            foreach ($array_lib as $mylib)
            {

                if(!(include($mylib)))
                {
                    echo "$include_error '$mylib'.\n<br />";
                    echo "$int_error";
                    return(1);
                }
            }

            if(!os_check_config($ossec_dir, $ossec_max_alerts_per_page,
                         $ossec_search_level, $ossec_search_time,
                         $ossec_refresh_time))
            {
                echo "$int_error";
                return(1);
            }

			switch ($USER_f) 
            {
			case "s":
                if(!include("site/search.php"))
                {
                    echo "$int_error";
                    return(1);
                }
			   break;
            case "sf":
                if(!include("site/searchfw.php"))
                {
                    echo "$int_error";
                    return(1);
                }
                break;
			case "m":
                if(!include("site/main.php"))
                {
                    echo "$int_error";
                    return(1);
                }
			   break;
			case "u":
                if(!include("site/user_mapping.php"))
                {
                    echo "$int_error";
                    return(1);
                }
			   break;
			case "t":
                if(!include("site/stats.php"))
                {
                    echo "$int_error";
                    return(1);
                }
			   break;
			case "a":
                if(!include("site/help.php"))
                {
                    echo "$int_error";
                    return(1);
                }
			   break;	
            case "i":
                if(!include("site/syscheck.php"))
                {
                    echo "$int_error";
                    return(1);
                }
                break;
			default:
                echo '<b class="red">Invalid argument.</b>';
                return(1);						   
			}
            
           ?>


    <!-- END: content -->
    <br /><br />
    <br /><br />
    <br /><br />
    <br /><br />
    </div>
    </div>
            	

<?php
    /* Including the footer */
    if(!(include("site/footer.html")))
    {
        echo "$include_error 'site/footer.html'.\n<br />";
        echo "$int_error";
        return(1);
    }
?>
    </div>
</body>
</html>
