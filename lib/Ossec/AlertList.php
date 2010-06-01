<?php
/* @(#) $Id: AlertList.php,v 1.6 2008/03/03 15:12:18 dcid Exp $ */

/**
 * Ossec Framework
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @category   Ossec
 * @package    Ossec
 * @version    $Id: AlertList.php,v 1.6 2008/03/03 15:12:18 dcid Exp $
 * @author     Chris Abernethy
 * @copyright  Copyright (c) 2007-2008, Daniel B. Cid <dcid@ossec.net>, All rights reserved.
 * @license    http://www.gnu.org/licenses/gpl-3.0.txt GNU Public License
 */

require_once 'Ossec/Histogram.php';

/**
 * 
 * 
 * @category   Ossec
 * @package    Ossec
 * @copyright  Copyright (c) 2007-2008, Daniel B. Cid, All rights reserved.
 */
class Ossec_AlertList {

    var $_alerts = array( );
    var $_earliest = null;
    var $_latest   = null;

    var $_id_histogram    = null;
    var $_srcip_histogram = null;
    var $_level_histogram = null;

    function Ossec_AlertList( ) {
        $this->_id_histogram    = new Ossec_Histogram();
        $this->_level_histogram = new Ossec_Histogram();
        $this->_srcip_histogram = new Ossec_Histogram();
    }

    /**
     * Return the array of alerts.
     *
     * @return array
     */
    function alerts( ) {
        return $this->_alerts;
    }

    function addAlert( $alert ) {

        $this->_id_histogram   ->count( "{$alert->id}"    );
        $this->_srcip_histogram->count( "{$alert->srcip}" );
        $this->_level_histogram->count( "{$alert->level}" );

        // If the event is older than the earliest event, update
        // the earliest event.

        if( is_null( $this->_earliest )
        || ( $alert->time < $this->_earliest->time ) ) {
            $this->_earliest = $alert;
        }

        // If the event is newer than the latest event, update
        // the latest event. In case of a tie, always update.

        if( is_null( $this->_latest )
        || ( $alert->time >= $this->_latest->time ) ) {
            $this->_latest = $alert;
        }

        $this->_alerts[] = $alert;

    }

    function earliest() {
        return $this->_alerts[0];
    }

    function latest() {
        return $this->_latest;
    }

    function size( ) {
        return count( $this->_alerts );
    }

    function toHTML( ) {

        ob_start();

        $first = $this->earliest();
        $first = date('Y M d H:i:s', $first->time );
        $last  = $this->latest();
        $last  = date('Y M d H:i:s', $last->time ); ?>

        <div id="alert_list_nav">
            <?php echo $this->_tallyNav( $this->_level_histogram, 'level', 'severity' , '+Severity breakdown' ) ?>
            <?php echo $this->_tallyNav( $this->_id_histogram   , 'id'   , 'rule'     , '+Rules breakdown'    ) ?>
            <?php echo $this->_tallyNav( $this->_srcip_histogram, 'srcip', 'Source IP', '+Src IP breakdown'   ) ?>
        </div>
        <br />

        <table width="100%">
            <tr><td><b>First event</b> at <a href="#lt"><?php echo $first ?></a></td></tr>
            <tr><td><b>Last event</b> at <a href="#ft"><?php echo $last ?></a></td></tr>
        </table>
        <br />

        <h2>Alert list</h2>
        <div id="alert_list_content">
            <a name="ft" ></a>
            <?php foreach( array_reverse($this->_alerts) as $alert ): ?>
                <?php echo $alert->toHtml( ) ?>
            <?php endforeach; ?>
            <a name="lt" ></a>
        </div>

        <script type="text/javascript">

            // Get a list of all key/id combos. This is used in the Show
            // Only and Clear Restrictions functionality.

            var cnames = [];
            $$('#alert_list_content div.alert').each(function(el){
              cnames = cnames.concat($w(el.className).grep(/^(id|level|srcip)/)).uniq();
            });

            // Open or close the navigation link set for the key clicked.

            $$('#alert_list_nav div.toggle').each(function(el){
                Event.observe( el, 'click', function(e) { Event.stop(e);
                    el.childElements().grep(new Selector("div.details")).invoke('toggle');
                });
            });

            // Clear the current restrictions for a key. Show all alerts for
            // that key type, and update the nav for all ids in that key.

            $$('#alert_list_nav a.clear').each(function(el){
                var mycname = $w(el.className).grep(/^(id|level|srcip)/);
                var re_type = new RegExp('^' + (''+mycname).split('_')[0]);
                Event.observe( el, 'click', function(e){ Event.stop(e);
                    cnames.grep(re_type).each(function(c){
                        $$('#alert_list_content .' + c ).invoke('show');
                        $('showing_' + c).show(); $('hiding_' + c).hide();
                    });
                })
            });

            // Hide all alerts having the key/id clicked and update the
            // nav links for that id.

            $$('#alert_list_nav a.hide').each(function(el){
                var mycname = $w(el.className).grep(/^(id|level|srcip)/);
                Event.observe( el, 'click', function(e){ Event.stop(e);
                    $$('#alert_list_content .' + mycname ).invoke('hide');
                    $('showing_' + mycname, 'hiding_' + mycname).invoke('toggle');
                })
            });

            // Hide all alerts not having the key/id clicked and update
            // the nav links for the rest of the ids in the key clicked.

            $$('#alert_list_nav a.only').each(function(el){
                var mycname = $w(el.className).grep(/^(id|level|srcip)/);
                var re_type = new RegExp('^' + (''+mycname).split('_')[0]);
                Event.observe( el, 'click', function(e){ Event.stop(e);
                    $$('#alert_list_content div.alert').each(function(el){
                        el.hasClassName(mycname) ? null : el.hide();
                    });
                    cnames.without(mycname).grep(re_type).each(function(c){
                        $('showing_' + c).hide(); $('hiding_' + c).show();
                    });
                });
            });

            // Show all alerts for the key/id clicked and update the nav
            // links for that id.

            $$('#alert_list_nav a.show').each(function(el){
                var mycname = $w(el.className).grep(/^(id|level|srcip)/);
                Event.observe( el, 'click', function(e){ Event.stop(e);
                    $$('#alert_list_content .' + mycname ).invoke('show');
                    $('showing_' + mycname, 'hiding_' + mycname).invoke('toggle');
                })
            });

        </script>
        <?php
        
        return ob_get_clean( );

    }

    function _tallyNav($histogram, $key, $description, $title ) {

        // Obtain copy of histogram and sort in reverse order by value.

        $tally = $histogram->getRaw( );
        arsort( $tally ); ?>

        <div class="alert_list_nav">
            <div class="asmall toggle">
                <a href="#" title="<?php echo $title ?>" class="black bigg" style="font-weight:bold;"><?php echo $title ?></a>
                <div class="asmall details" style="display:none">
                    <?php foreach($tally as $id => $count): ?>
                        <div id="showing_<?php echo $key ?>_<?php echo $id ?>" class="asmall">
                            Showing <?php echo $count ?> alert(s) from <b><?php echo $key ?> <?php echo $id ?></b>
                            <a href="#" class="asmall hide <?php echo $key ?>_<?php echo $id ?>" title="Hide this <?php echo $key ?>">(hide)</a>
                            <a href="#" class="asmall only <?php echo $key ?>_<?php echo $id ?>" title="Show only this <?php echo $key ?>">(show only)</a>
                        </div>
                        <div id="hiding_<?php echo $key ?>_<?php echo $id ?>" class="asmall" style="display:none;">
                            Hiding <?php echo $count ?> alert(s) from <b><?php echo $key ?> <?php echo $id ?></b>
                            <a href="#" class="asmall show <?php echo $key ?>_<?php echo $id ?>" title="Hiding <?php echo $key ?>">(show)</a>
                        </div>
                    <?php endforeach; ?>
                    <a href="#" class="asmall clear <?php echo $key ?>" title="Clear <?php echo $description ?> restrictions">Clear <?php echo $key ?> restrictions</a>
                </div>
            </div>
        </div><?php

    }

};

?>
