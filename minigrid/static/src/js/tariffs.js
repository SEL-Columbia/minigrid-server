var Flatpickr = require('flatpickr');
require("flatpickr.css");

var date_input = document.querySelector(".flatpickr");

if (timestamp) date_input.value = timestamp;
else date_input.value = new Date(Date.now()).toISOString();

const fp_date = new Flatpickr(date_input,
	{
		enableTime: true,
		time_24hr: true,
		minuteIncrement: 1
	})