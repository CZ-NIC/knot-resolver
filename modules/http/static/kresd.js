var colours = ['#ffffd9','#edf8b1','#c7e9b4','#7fcdbb','#41b6c4','#1d91c0','#225ea8','#253494','#081d58'];
var latency = ['1ms', '10ms', '50ms', '100ms', '250ms', '500ms', '1000ms', '1500ms', 'slow'];
var palette = new Rickshaw.Color.Palette( { scheme: 'colorwheel' } );
var Socket = "MozWebSocket" in window ? MozWebSocket : WebSocket;

$(function() {
	/* Initialize snippets. */
	$('section').each(function () {
		const heading = $(this).find('h2');
		$('#modules-dropdown').append('<li><a href="#'+this.id+'">'+heading.text()+'</a></li>');
	});
	/* Latency has its own palette */
	var series = [];
	var data = [];
	function pushSeries(name, color) {
		data[name] = [];
		var s = {
			name: name,
			color: color,
			data: data[name],
			stroke: true,
			preserve: true
		}
		series.push(s);
		return s;
	}
	/* Render latency metrics as sort of a heatmap */
	for (var i in latency) {
		var s = pushSeries('answer.'+latency[i], colours[colours.length - i - 1]);
		s.name = 'RTT '+latency[i];
		s.renderer = 'bar';
	}
	/* Render other interesting metrics as lines (hidden by default) */
	var metrics = {
		'answer.noerror': 'NOERROR',
		'answer.nodata': 'NODATA',
		'answer.nxdomain': 'NXDOMAIN',
		'answer.servfail': 'SERVFAIL',
		'answer.dnssec': 'DNSSEC',
		'cache.hit': 'Cache hit',
		'cache.miss': 'Cache miss',
		'worker.udp': 'Outgoing UDP',
		'worker.tcp': 'Outgoing TCP',
		'worker.ipv4': 'Outgoing IPv4',
		'worker.ipv6': 'Outgoing IPv6',
	};
	for (var key in metrics) {
		var s = pushSeries(key, palette.color());
		s.name = metrics[key];
		s.renderer = 'line';
		s.disabled = true;
	}
	/* Define how graph looks like. */
	var graphContainer = $('#stats');
	var graph = new Rickshaw.Graph( {
		element: document.getElementById('chart'),
		height: 350,
		width: graphContainer.innerWidth() - 200,
		renderer: 'multi',
		series: series,
	});
	var x_axis = new Rickshaw.Graph.Axis.Time( {
		graph: graph,
		ticksTreatment: 'glow',
		element: document.querySelector("#x_axis"),
	} );
	var y_axis = new Rickshaw.Graph.Axis.Y( {
		graph: graph,
		orientation: 'left',
		ticksTreatment: 'glow',
		tickFormat: function (y) {
			return Rickshaw.Fixtures.Number.formatKMBT(y) + ' pps';
		},
		element: document.querySelector("#y_axis")
	} );
	var graphHover = new Rickshaw.Graph.HoverDetail({graph: graph});
	var legend = new Rickshaw.Graph.Legend({
		graph: graph,
		element: document.querySelector("#legend")
	});
	var highlighter = new Rickshaw.Graph.Behavior.Series.Highlight( {
		graph: graph,
		legend: legend
	} );
	var shelving = new Rickshaw.Graph.Behavior.Series.Toggle( {
		graph: graph,
		legend: legend
	} );
	/* Somehow follow the responsive design. */
	$(window).on('resize', function(){
		graph.configure({
			width: graphContainer.innerWidth() - 200,
		});
		graph.render();
	});
	graph.render();

	/* Data map */
	var fills = { defaultFill: '#F5F5F5' };
	for (var i in colours) {
		fills['q' + i] = colours[colours.length - 1 - i];
	}
	var map = new Datamap({
		element: document.getElementById('map'),
		fills: fills,
		data: {},
		height: 400,
		geographyConfig: {
			highlightOnHover: false,
			borderColor: '#ccc',
			borderWidth: 0.5,
			popupTemplate: function(geo, data) {
				return ['<div class="hoverinfo">',
					'<strong>', geo.properties.name, '</strong>',
					'<br>Queries: <strong>', data ? data.queries : '0', '</strong>',
					'</div>'].join('');
			}
		},
		bubblesConfig: {
			popupTemplate: function(geo, data) {
				return ['<div class="hoverinfo">',
					'<strong>', data.name, '</strong>',
					'<br>Queries: <strong>', data ? data.queries : '0', '</strong>',
					'<br>Average RTT: <strong>', data ? parseInt(data.rtt) : '0', ' ms</strong>',
					'</div>'].join('');
			}
		}
	});
	function colorBracket(rtt) {
		for (var i in latency) {
			if (rtt <= parseInt(latency[i])) {
				return 'q' + i;
			}
		}
		return 'q8';
	}
	function togeokey(lon, lat) {
		return lon.toFixed(0)+'#'+lat.toFixed(0);
	}

	/* Realtime updates over WebSockets */
	function pushMetrics(resp) {
		var now = Date.now() / 1000;
		for (var lb in resp) {
			var val = resp[lb];
			/* Push new datapoints */
			if (lb in data) {
				data[lb].push({x: now, y:val});
				if (data[lb].length > 100) {
					data[lb].shift();
				}
			}

		}
		graph.update();
	}

	var age = 0;
	var bubbles = [];
	var bubblemap = {};
	function pushUpstreams(resp) {
		if (resp == null) {
			return;
		}
		/* Get current maximum number of queries for bubble diameter adjustment */
		var maxQueries = 1;
		for (var key in resp) {
			var val = resp[key];
			if ('data' in val) {
				maxQueries = Math.max(maxQueries, resp[key].data.length)
			}
		}
		/* Update bubbles and prune the oldest */
		for (var key in resp) {
			var val = resp[key];
			if (!val.data) {
				continue;
			}
			var sum = val.data.reduce(function(a, b) { return a + b; });
			var avg = sum / val.data.length;
			var geokey = togeokey(val.location.longitude, val.location.latitude)
			var found = bubblemap[geokey];
			if (!found) {
				found = {
					name: [key],
					longitude: val.location.longitude,
					latitude: val.location.latitude,
					queries: 0,
					rtt: avg,
				}
				bubbles.push(found);
				bubblemap[geokey] = found;
			}
			/* Update bubble parameters */
			if (!(key in found.name)) {
				found.name.push(key);	
			}
			found.rtt = (found.rtt + avg) / 2.0;
			found.fillKey = colorBracket(found.rtt);
			found.queries = found.queries + val.data.length;
			found.radius = Math.max(5, 15*(val.data.length/maxQueries));
			found.age = age;
		}
		/* Prune bubbles not updated in a while. */
		for (var i in bubbles) {
			var b = bubbles[i];
			if (b.age <= age - 5) {
				bubbles.splice(i, 1)
				bubblemap[i] = null;
			}
		}
		map.bubbles(bubbles);
		age = age + 1;
	}

	/* WebSocket endpoints */
	var wsStats = (secure ? 'wss://' : 'ws://') + location.host + '/stats';
    var ws = new Socket(wsStats);
    ws.onmessage = function(evt) {
      var data = $.parseJSON(evt.data);
      pushMetrics(data.stats);
      pushUpstreams(data.upstreams);
    };
});