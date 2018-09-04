import $ from 'jquery';

export default function populateCardDeviceTable(info, device_connect_error) {
    $('.device-info>.card-info-row').remove();
    if (isEmpty(info)) {
        console.log('no device');
        if (isEmpty(device_connect_error)) {
            $('.device-info').append(`
                    <div class="card-info-row" id="no-card-message">
                        <strong><p>${'No device connected.'}</p><p>${'Try resetting your device'}</p></strong>
                    </div>
                `);
        }
        else {
            $('.device-info').append(`
                    <div class="card-info-row" id="no-card-message">
                        <strong><p>${'Error connecting to device.'}</p><p>${device_connect_error}</p></strong>
                    </div>
                `);
        }
    }
    else {
        Object.keys(info).forEach(key => {
            console.log('device', key, info[key]);
            if (key == "Connected Device") {
                $('.device-info').append(`
                    <div class="card-info-row">
                        <div class="card-info-col col-left"><strong>${key}</strong></div>
                        <div class="card-info-col col-right">${info[key]}</div>
                    </div>
                `);
            };
        });
    }
}

function isEmpty(obj) {
    if (obj==null) return true;
    for (var key in obj) {
        if (key == "Connected Device") {
            return false;
        }
    }
    return true;
}
