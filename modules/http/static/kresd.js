var colours = ["#081d58", "#253494", "#225ea8", "#1d91c0", "#41b6c4", "#7fcdbb", "#c7e9b4", "#edf8b1", "#edf8b1"];
var latency = ["slow", "1500ms", "1000ms", "500ms", "250ms", "100ms", "50ms", "10ms", "1ms"];
var Socket = "MozWebSocket" in window ? MozWebSocket : WebSocket;

$(function() {
	/* Helper functions */
	function colorBracket(rtt) {
		for (var i = latency.length - 1; i >= 0; i--) {
			if (rtt <= parseInt(latency[i])) {
				return 'q' + i;
			}
		}
		return 'q8';
	}
	function toGeokey(lon, lat) {
		return lon.toFixed(0)+'#'+lat.toFixed(0);
	}
	function updateVisibility(graph, metrics, id, toggle) {
		/* Some labels are aggregates */
		if (metrics[id] == null) {
			for (var key in metrics) {
				const m = metrics[key];
				if (m.length > 3 && m[3] == id) {
					graph.setVisibility(m[0], toggle);
				}
			}
		} else {
			graph.setVisibility(metrics[id][0], toggle);
		}
	}
	function formatNumber(n) {
	    with (Math) {
	        var base = floor(log(abs(n))/log(1000));
	        var suffix = 'KMB'[base-1];
	        return suffix ? String(n/pow(1000,base)).substring(0,3)+suffix : ''+n;
	    }
	}

	/* Initialize snippets. */
	$('section').each(function () {
		const heading = $(this).find('h2');
		$('#modules-dropdown').append('<li><a href="#'+this.id+'">'+heading.text()+'</a></li>');
	});

	/* Render other interesting metrics as lines (hidden by default) */
	var data = [];
	var last_metric = 15;
	var metrics = {
		'answer.noerror':    [0, 'NOERROR', null, 'By RCODE'],
		'answer.nodata':     [1, 'NODATA', null, 'By RCODE'],
		'answer.nxdomain':   [2, 'NXDOMAIN', null, 'By RCODE'],
		'answer.servfail':   [3, 'SERVFAIL', null, 'By RCODE'],
		'answer.dnssec':     [4, 'DNSSEC', null, 'By RCODE'],
		'cache.hit':         [5, 'Cache hit'],
		'cache.miss':        [6, 'Cache miss'],
		'cache.insert':      [7, 'Cache insert'],
		'cache.delete':      [8, 'Cache delete'],
		'worker.udp':        [9, 'Outgoing UDP'],
		'worker.tcp':        [10, 'Outgoing TCP'],
		'worker.ipv4':       [11, 'Outgoing IPv4'],
		'worker.ipv6':       [12, 'Outgoing IPv6'],
		'worker.concurrent': [13, 'Queries outstanding'],
		'worker.queries':    [14, 'Queries received/s'],
		'worker.dropped':    [15, 'Queries dropped'],
	};
	
	/* Render latency metrics as sort of a heatmap */
	var series = {};
	for (var i in latency) {
		const name = 'RTT '+latency[i];
		const colour = colours[colours.length - i - 1];
		last_metric = last_metric + 1;
		metrics['answer.'+latency[i]] = [last_metric, name, colour, 'latency'];
		series[name] = {fillGraph: true, color: colour, fillAlpha: 1.0};
	}
	var labels = ['x'];
	var visibility = [];
	for (var key in metrics) {
		labels.push(metrics[key][1]);
		visibility.push(false);
	}
	
	/* Define how graph looks like. */
	const graphContainer = $('#stats');
    const graph = new Dygraph(
        document.getElementById("chart"),
        data, {
			labels: labels,
			labelsUTC: true,
			labelsShowZeroValues: false,
			visibility: visibility,
			axes: { y: {
				axisLabelFormatter: function(d) {
					return formatNumber(d) + 'pps';
				},
			}},
			series: series,
			strokeWidth: 1,
			highlightSeriesOpts: {
				strokeWidth: 3,
				strokeBorderWidth: 1,
				highlightCircleSize: 5,
			},
		});
    /* Define metric selector */
    const chartSelector = $('#chart-selector').selectize({
		maxItems: null,
		create: false,
		onItemAdd: function (x) { updateVisibility(graph, metrics, x, true); },
		onItemRemove: function (x) { updateVisibility(graph, metrics, x, false); }
	})[0].selectize;
	for (var key in metrics) {
		const m = metrics[key];
		const groupid = m.length > 3 ? m[3] : key.split('.')[0];
		const group = m.length > 3 ? m[3] : m[1].split(' ')[0];
		/* Latency has a special aggregated item */
		if (group != 'latency') {
			chartSelector.addOptionGroup(groupid, { label: group } );
			chartSelector.addOption({ text: m[1], value: key, optgroup: groupid });
		}
	}
	/* Add latency as default */
	chartSelector.addOption({ text: 'Latency', value: 'latency', optgroup: 'Queries' });
	chartSelector.addItem('latency');
	/* Add stacked graph control */
	$('#chart-stacked').on('change', function(e) {
		graph.updateOptions({stackedGraph: this.checked});
    }).click();

	/* Data map */
	var fills = { defaultFill: '#F5F5F5' };
	for (var i in colours) {
		fills['q' + i] = colours[i];
	}
	const map = new Datamap({
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

	/* Realtime updates over WebSockets */
	function pushMetrics(resp, now, buffer) {
		var line = new Array(last_metric + 1);
		line[0] = new Date(now * 1000);
		for (var lb in resp) {
			/* Push new datapoints */
			const metric = metrics[lb];
			if (metric) {
				line[metric[0] + 1] = resp[lb];
			}
		}
		/* Buffer graph  changes. */
		data.push(line);
		if (!buffer) {
			graph.updateOptions( { 'file': data } );
		}
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
			if (!val.data || !val.location || val.location.longitude == null) {
				continue;
			}
			var sum = val.data.reduce(function(a, b) { return a + b; });
			var avg = sum / val.data.length;
			var geokey = toGeokey(val.location.longitude, val.location.latitude)
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
		var data = JSON.parse(evt.data);
		if (data[0]) {
			if (data.length > 0) {
				pushUpstreams(data[data.length - 1].upstreams);
			}
			for (var i in data) {
				pushMetrics(data[i].stats, data[i].time, true);
			}
			graph.updateOptions( { 'file': data } );
		} else {
			pushMetrics(data.stats, data.time);
			pushUpstreams(data.upstreams);
		}

	};
});