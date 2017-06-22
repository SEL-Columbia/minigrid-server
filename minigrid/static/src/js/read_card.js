'use strict';

import $ from 'jquery';
import SockJS from 'sockjs-client';
import populateCardInfoTable from './populate_card_info.js';


(function(){

    let conn = new SockJS(http_protocol + '://' + window.location.host + '/cardconn');
        let received_info;
        let card_read_error;
        let device_active;

        console.log('Connecting...');

        conn.onopen = function() {
            console.log('Connected.');
        };

        conn.onmessage = function(e) {
            console.log('Received: ' + JSON.stringify(e.data['received_info']));
            received_info = e.data['received_info'];
            card_read_error = e.data['card_read_error'];

            if (e.data['device_active']!==device_active) {
                populateCardInfoTable(received_info, card_read_error);
            };
        };

        conn.onclose = function() {
            console.log('Disconnected.');
            conn = null;
        };

})();
