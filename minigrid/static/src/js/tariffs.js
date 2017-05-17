var Flatpickr = require('flatpickr');
require("flatpickr.css");


var date_input = document.querySelector(".flatpickr-date");
var time_input = document.querySelector(".flatpickr-time");

const fp_date = new Flatpickr(date_input,
	{
		dateFormat: "d-m-Y",
		altInput: true,
	})

const fp_time = new Flatpickr(time_input,
	{
		enableTime: true,
		noCalendar: true,
		time_24hr: true,
		defaultDate: "00:00"
	})