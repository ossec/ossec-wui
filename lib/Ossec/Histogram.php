<?php
/* @(#) $Id: Histogram.php,v 1.3 2008/03/03 15:12:18 dcid Exp $ */

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
 * @version    $Id: Histogram.php,v 1.3 2008/03/03 15:12:18 dcid Exp $
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
class Ossec_Histogram {

    /**
     * Histogram data stored as a hash.
     *
     * @var array
     */
    var $_histogram = array();

    /**
     * Increment the counter for the specified key by the
     * given number (one, by default).
     *
     * @param string $key
     * @param integer $num
     */
    function count( $key, $num = 1 ) {
        if(! array_key_exists( $key, $this->_histogram ) ) {
            $this->_histogram[$key] = 0;
        }
        $this->_histogram[$key] += intval( $num );
    }

    /**
     * Return raw histogram data.
     *
     * @return array
     */
    function getRaw( ) {
        return $this->_histogram;
    }

};

?>