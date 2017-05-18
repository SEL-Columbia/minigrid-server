var Flatpickr = require('flatpickr');
require("flatpickr.css");

var date_input = document.querySelector(".flatpickr-date");
var time_input = document.querySelector(".flatpickr-time");

if (timestamp) {
	var datetime = timestamp.split('T')
	var date = datetime[0];
	var time = datetime[1];

	date_input.value = date;
	time_input.value = time;
}

const fp_date = new Flatpickr(date_input,
	{
		dateFormat: "Y-m-d",
		altInput: true,
	})

const fp_time = new Flatpickr(time_input,
	{
		enableTime: true,
		noCalendar: true,
		time_24hr: true,
	})