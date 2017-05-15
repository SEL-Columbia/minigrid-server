'use strict';

import $ from 'jquery';
import SockJS from 'sockjs-client';
import populateCardInfoTable from './populate_card_info.js';


(function(){
    
    //disable form submit until card is on device
    $('form.credit-form').submit(false);
    const input = document.getElementById('card-value');

    let conn = new SockJS(http_protocol + '://' + window.location.host + '/cardconn');
        let received_info;
        let device_active;

        console.log('Connecting...');

        conn.onopen = function() {
            console.log('Connected.');
        };

        conn.onmessage = function(e) {
            console.log('Received: ' + JSON.stringify(e.data['received_info']));
            received_info = e.data['received_info'];

            if (e.data['device_active']!==device_active) {
                device_active = e.data['device_active'];
                if (e.data['device_active']) input.disabled = false;
                else input.disabled = true;
                populateCardInfoTable(received_info);
            };
        };

        conn.onclose = function() {
            console.log('Disconnected.');
            conn = null;
        };


})();
