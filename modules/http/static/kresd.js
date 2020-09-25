/* SPDX-License-Identifier: GPL-3.0-or-later */
var colours = ["#081d58", "#253494", "#225ea8", "#1d91c0", "#41b6c4", "#7fcdbb", "#c7e9b4", "#edf8b1", "#edf8b1"];
var latency = ["slow", "1500ms", "1000ms", "500ms", "250ms", "100ms", "50ms", "10ms", "1ms"];
var Socket = "MozWebSocket" in window ? MozWebSocket : WebSocket;
let isGraphPaused = false;

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
	var last_metric = 17;
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
		'worker.udp':        [9, 'UDP queries'],
		'worker.tcp':        [10, 'TCP queries'],
		'worker.ipv4':       [11, 'IPv4 queries'],
		'worker.ipv6':       [12, 'IPv6 queries'],
		'worker.concurrent': [13, 'Concurrent requests'],
		'worker.queries':    [14, 'Queries received/s'],
		'worker.dropped':    [15, 'Queries dropped'],
		'worker.usertime':   [16, 'CPU (user)', null, 'Workers'],
		'worker.systime':    [17, 'CPU (sys)', null, 'Workers'],
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
		var line = new Array(labels.length);
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
		if (data.length > 1000) {
			data.shift();
		}
		if ( !buffer ) {
			if ( !isGraphPaused ) {
				graph.updateOptions( { 'file': data } );
			}
		}
	}

	var age = 0;
	var bubbles = [];
	var bubblemap = {};
	function pushUpstreams(resp) {
		if (resp == null) {
			$('#map-container').hide();
			return;
		} else {
			$('#map-container').show();
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

	/* Per-worker information */
	function updateRate(x, y, dt) {
		return (100.0 * ((x - y) / dt)).toFixed(1);
	}
	function updateWorker(row, next, data, timestamp, buffer) {
		const dt = timestamp - data.timestamp;
		const cell = row.find('td');
		/* Update spark lines and CPU times first */
		if (dt > 0.0) {
			const utimeRate = updateRate(next.usertime, data.last.usertime, dt);
			const stimeRate = updateRate(next.systime, data.last.systime, dt);
			cell.eq(1).find('span').text(utimeRate + '% / ' + stimeRate + '%');
			/* Update sparkline graph */
			data.data.push([new Date(timestamp * 1000), Number(utimeRate), Number(stimeRate)]);
			if (data.data.length > 60) {
				data.data.shift();
			}
			if (!buffer) {
				data.graph.updateOptions( { 'file': data.data } );
			}
		}
		/* Update other fields */
		if (!buffer) {
			cell.eq(2).text(formatNumber(next.rss) + 'B');
			cell.eq(3).text(next.pagefaults);
			cell.eq(4).text('Healthy').addClass('text-success');
		}
	}

	var workerData = {};
	function pushWorkers(resp, timestamp, buffer) {
		if (resp == null) {
			return;
		}
		const workerTable = $('#workers');
		for (var pid in resp) {
			var row = workerTable.find('tr[data-pid='+pid+']');
			if (row.length == 0) {
				row = workerTable.append(
					'<tr data-pid='+pid+'><td>'+pid+'</td>'+
					'<td><div class="spark" id="spark-'+pid+'" /><span /></td><td></td><td></td><td></td>'+
					'</tr>');
				/* Create sparkline visualisation */
				const spark = row.find('#spark-'+pid);
				spark.css({'margin-right': '1em', width: '80px', height: '1.4em'});
				workerData[pid] = {timestamp: timestamp, data: [[new Date(timestamp * 1000),0,0]], last: resp[pid]};
				const workerGraph = new Dygraph(spark[0],
			        workerData[pid].data, {
			        	valueRange: [0, 100],
			        	legend: 'never',
						axes : {
							x : {
								drawGrid: false,
								drawAxis : false,
							},
							y : {
								drawGrid: false,
								drawAxis : false,
							}
						},
						labels: ['x', '%user', '%sys'],
						labelsDiv: '',
						stackedGraph: true,
			        }
				);
				workerData[pid].graph = workerGraph;
			}
			updateWorker(row, resp[pid], workerData[pid], timestamp, buffer);
			/* Track last datapoint */
			workerData[pid].last = resp[pid];
			workerData[pid].timestamp = timestamp;
		}
		/* Prune unhealthy PIDs */
		if (!buffer) {
			workerTable.find('tr').each(function () {
				const e = $(this);
				if (!(e.data('pid') in resp)) {
					const healthCell = e.find('td').last();
					healthCell.removeClass('text-success')
					healthCell.text('Dead').addClass('text-danger');
				}
			});
		}
	}

	/* WebSocket endpoints */
	var wsStats = ('https:' == document.location.protocol ? 'wss://' : 'ws://') + location.host + '/stats';
	var ws = new Socket(wsStats);
	ws.onmessage = function(evt) {
		var data = JSON.parse(evt.data);
		if (data[0]) {
			if (data.length > 0) {
				pushUpstreams(data[data.length - 1].upstreams);
			}
			/* Buffer datapoints and redraw last */
			for (var i in data) {
				const is_last = (i == data.length - 1);
				pushWorkers(data[i].workers, data[i].time, !is_last);
				pushMetrics(data[i].stats, data[i].time, !is_last);
			}
		} else {
			pushUpstreams(data.upstreams);
			pushWorkers(data.workers, data.time);
			pushMetrics(data.stats, data.time);
		}
	};

	chartElement.addEventListener( 'mouseover', ( event ) =>
	{
		isGraphPaused = true;
	}, false );

	chartElement.addEventListener( 'mouseout', ( event ) =>
	{
		isGraphPaused = false;
	}, false );

});
