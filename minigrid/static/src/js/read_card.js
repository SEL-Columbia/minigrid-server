'use strict';

import $ from 'jquery';
import SockJS from 'sockjs-client';
import populateCardInfoTable from './populate_card_info.js';
import populateCardDeviceTable from './populate_device_info.js';


(function(){

    let conn = new SockJS(http_protocol + '://' + window.location.host + '/cardconn');
        let received_info;
        let card_read_error;
        let device_active;
        let device_connect_error;

        console.log('Connecting...');

        conn.onopen = function() {
            console.log('Connected.');
        };

        conn.onmessage = function(e) {
            console.log('Received: ' + JSON.stringify(e.data['received_info']));
            received_info = e.data['received_info'];
            card_read_error = e.data['card_read_error'];
            device_connect_error = {}; // future use

            populateCardDeviceTable(received_info, device_connect_error);
            if (e.data['device_active']!==device_active) {
                populateCardInfoTable(received_info, card_read_error);
            };
        };

        conn.onclose = function() {
            console.log('Disconnected.');
            conn = null;
        };

})();
