'use strict';

import $ from 'jquery';
import SockJS from 'sockjs-client';


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

    function populateCardInfoTable(info) {
        $('.card-info>.card-info-row').remove();
        if (isEmpty(info)) {
            $('form.credit-form').submit(false);
            $('.card-info').append(`
                    <div class="card-info-row" id="no-card-message">
                        <strong><p>${'No card info received.'}</p><p>${'Is there a card on the device?'}</p></strong>
                    </div>
                `);
        } else {
            //enable form submit
            $('form').unbind('submit');
            Object.keys(info).forEach(key => {
                console.log('here', key, info[key]);
                $('.card-info').append(`
                    <div class="card-info-row">
                        <div class="card-info-col col-left"><strong>${key}</strong></div>
                        <div class="card-info-col col-right">${info[key]}</div>
                    </div>
                `);
            });
        }
    }

    function isEmpty(obj) {
        if (obj==null) return true;
        for (var key in obj) {
            return false; 
        }
        return true;
    }


})();
