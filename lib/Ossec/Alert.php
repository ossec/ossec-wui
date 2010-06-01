<?php
/* @(#) $Id: Alert.php,v 1.4 2008/03/03 15:12:18 dcid Exp $ */

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
 * @version    $Id: Alert.php,v 1.4 2008/03/03 15:12:18 dcid Exp $
 * @author     Chris Abernethy
 * @copyright  Copyright (c) 2007-2008, Daniel B. Cid <dcid@ossec.net>, All rights reserved.
 * @license    http://www.gnu.org/licenses/gpl-3.0.txt GNU Public License
 */

/**
 * 
 * 
 * @category   Ossec
 * @package    Ossec
 * @copyright  Copyright (c) 2007-2008, Daniel B. Cid, All rights reserved.
 */
class Ossec_Alert {

    var $time;
    var $id;
    var $level;
    var $user;
    var $srcip;
    var $description;
    var $location;
    var $msg;

    function toHtml( ) {

        $date    = date('Y M d H:i:s', $this->time);
        $id_link = "<a href=\"http://www.ossec.net/wiki/index.php/Rule:{$this->id}\">{$this->id}</a>";
        $message = join( '<br/>', $this->msg );

        $srcip = "";
        if( $this->srcip != '(none)') {
            $srcip = "<span style=\"font-weight:bold;\">Src IP</span>: {$this->srcip}<br/>";
        }

        $class = "level_{$this->level} id_{$this->id} srcip_{$this->srcip}";

        return <<<HTML
        <div class="alert $class">
            <span style="font-weight:bold;">$date</span>
            Rule Id: $id_link
            level: {$this->level}<br />
            <span style="font-weight:bold;">Location:</span> {$this->location}<br />
            $srcip
            <span style="font-weight:bold;">{$this->description}</span>
            <div class="msg">
                $message
                <br />
            </div>
        </div>
HTML;
    }
};

?>
