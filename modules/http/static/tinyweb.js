// Unit conversion
function tounit(d) {
	d = parseInt(d);
	if (d < 1000) return d.toFixed(0);
	else if (d < 1000000) return (d / 1000.0).toFixed(1) + 'K';
	else return (d / 1000000.0).toFixed(1) + 'M';
}
// Set up UI and pollers
window.onload = function() {
	var statsLabels = ['cached', '10ms', '100ms', '1000ms', 'slow'];
	var statsHistory = [];
	var now = Date.now();
	for (i = 0; i < statsLabels.length; ++i) {
		statsHistory.push({ label: 'Layer ' + statsLabels[i], values: [{time: now, y:0}] });
		$('.stats-legend').append('<li class="l-' + statsLabels[i] + '">' + statsLabels[i]);
	}
	var statsChart = $('#stats').epoch({
		type: 'time.bar',
		axes: ['right', 'bottom'],
		ticks: { right: 2 },
		margins: { right: 60 },
		tickFormats: {
			right: function(d) { return tounit(d) + ' pps'; },
			bottom: function(d) { return new Date(d).toTimeString().split(' ')[0]; },
		},
		data: statsHistory
	});

	/*
	 * Realtime updates over WebSockets
	 */
	function pushMetrics(resp) {
		var now = Date.now();
		var next = [];
		for (i = 0; i < statsLabels.length; ++i) {
			var val = resp['answer.' + statsLabels[i]];
			next.push({time: now, y: val});
		}
		statsChart.push(next);
	}

	/* WebSocket endpoints */
	var wsStats = 'ws://' + location.host + '/stats';
    var Socket = "MozWebSocket" in window ? MozWebSocket : WebSocket;
    var ws = new Socket(wsStats);
    ws.onmessage = function(evt) {
      var data = $.parseJSON(evt.data);
      pushMetrics(data);
    };
}
