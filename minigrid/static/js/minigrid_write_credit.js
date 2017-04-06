'use strict';

(function(){

    const input = document.getElementById('card-value');
    let obj;

    setInterval(()=>{
      const request = new XMLHttpRequest();
      request.open('GET', '/device_json');
      
      request.onload = ()=>{
        if (request.status >= 200 && request.status < 400) {
          console.log('success');
          obj = JSON.parse(request.response);

          console.log(obj)

          if (obj.device_active) {
              input.disabled = false;
          } else {
              input.disabled = true;
          }
        } else {
          console.log('We reached our target server, but it returned an error');
        }
      };

      request.onerror = ()=>{
        console.log('There was a connection error of some sort');
      };

      request.send();

    }, 2000);
})();