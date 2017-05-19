var Flatpickr = require('flatpickr');
require("flatpickr.css");

var date_input = document.querySelector(".flatpickr");

if (timestamp) date_input.value = timestamp;

const fp_date = new Flatpickr(date_input,
	{
		enableTime: true,
		time_24hr: true
	})