'use strict';

import $ from 'jquery';
import SockJS from 'sockjs-client';

(function(){

    const input = document.getElementById('card-value');
    let conn = new SockJS(http_protocol + '://' + window.location.host + '/cardconn');

        console.log('Connecting...');

        conn.onopen = function() {
            console.log('Connected.');
        };

        conn.onmessage = function(e) {
            console.log('Received: ' + e.data);
            if (e.data) input.disabled = false;
            else input.disabled = true;
        };

        conn.onclose = function() {
            console.log('Disconnected.');
            conn = null;
        };

})();