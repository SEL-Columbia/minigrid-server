import $ from 'jquery';

export default function populateNotification(info, alert_error) {
    $('.notification-alert>.alert-row').remove();
    if (isEmpty(info)) {
        console.log('no alert');
        if (!isEmpty(alert_error)) {
            $('.notification-alert').append(`
                <div class="alert-row alert alert-warning">
                    <strong>${alert_error}</strong>
                </div>
            `);
        }
    }
    else {
        console.log('alert',info);
        $('.notification-alert').append(`
            <div class="alert-row alert ${info['type']}">
                <strong>${info['notification']}</strong>
            </div>
        `);
    }
}

function isEmpty(obj) {
    if (obj==null) return true;
    for (var key in obj) {
        return false;
    }
    return true;
}
