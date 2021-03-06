import $ from 'jquery';

export default function populateCardInfoTable(info, card_read_error) {
    $('.card-info>.card-info-row').remove();
    if (isEmpty(info)) {
        if (isEmpty(card_read_error)) {
            $('.card-info').append(`
                    <div class="card-info-row" id="no-card-message">
                        <strong><p>${'No card info received.'}</p><p>${'Is there a card on the device?'}</p></strong>
                    </div>
                `);
        }
        else {
            $('.card-info').append(`
                    <div class="card-info-row" id="no-card-message">
                        <strong><p>${'Error reading card.'}</p><p>${card_read_error}</p></strong>
                    </div>
                `);
        }
    }
    else {
        Object.keys(info).forEach(key => {
            console.log('here', key, info[key]);
            if (key != "Connected Device") {
                $('.card-info').append(`
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
        if (key != "Connected Device") {
            return false;
        }
    }
    return true;
}
