// Country code conversion
var iso2_to_iso3 = {
	"AF": "AFG", "AL": "ALB", "DZ": "DZA", "AS": "ASM", "AD": "AND", "AO": "AGO", "AI": "AIA", "AQ": "ATA", "AG": "ATG", "AR": "ARG", "AM": "ARM", "AW": "ABW", "AU": "AUS", "AT": "AUT", "AZ": "AZE", "BS": "BHS", "BH": "BHR", "BD": "BGD", "BB": "BRB", "BY": "BLR", "BE": "BEL", "BZ": "BLZ", "BJ": "BEN", "BM": "BMU", "BT": "BTN", "BO": "BOL", "BA": "BIH", "BW": "BWA", "BV": "BVT", "BR": "BRA", "IO": "IOT", "VG": "VGB", "BN": "BRN", "BG": "BGR", "BF": "BFA", "BI": "BDI", "KH": "KHM", "CM": "CMR", "CA": "CAN", "CV": "CPV", "KY": "CYM", "CF": "CAF", "TD": "TCD", "CL": "CHL", "CN": "CHN", "CX": "CXR", "CC": "CCK", "CO": "COL", "KM": "COM", "CD": "COD", "CG": "COG", "CK": "COK", "CR": "CRI", "CI": "CIV", "CU": "CUB", "CY": "CYP", "CZ": "CZE", "DK": "DNK", "DJ": "DJI", "DM": "DMA", "DO": "DOM", "EC": "ECU", "EG": "EGY", "SV": "SLV", "GQ": "GNQ", "ER": "ERI", "EE": "EST", "ET": "ETH", "FO": "FRO", "FK": "FLK", "FJ": "FJI", "FI": "FIN", "FR": "FRA", "GF": "GUF", "PF": "PYF", "TF": "ATF", "GA": "GAB", "GM": "GMB", "GE": "GEO", "DE": "DEU", "GH": "GHA", "GI": "GIB", "GR": "GRC", "GL": "GRL", "GD": "GRD", "GP": "GLP", "GU": "GUM", "GT": "GTM", "GN": "GIN", "GW": "GNB", "GY": "GUY", "HT": "HTI", "HM": "HMD", "VA": "VAT", "HN": "HND", "HK": "HKG", "HR": "HRV", "HU": "HUN", "IS": "ISL", "IN": "IND", "ID": "IDN", "IR": "IRN", "IQ": "IRQ", "IE": "IRL", "IL": "ISR", "IT": "ITA", "JM": "JAM", "JP": "JPN", "JO": "JOR", "KZ": "KAZ", "KE": "KEN", "KI": "KIR", "KP": "PRK", "KR": "KOR", "KW": "KWT", "KG": "KGZ", "LA": "LAO", "LV": "LVA", "LB": "LBN", "LS": "LSO", "LR": "LBR", "LY": "LBY", "LI": "LIE", "LT": "LTU", "LU": "LUX", "MO": "MAC", "MK": "MKD", "MG": "MDG", "MW": "MWI", "MY": "MYS", "MV": "MDV", "ML": "MLI", "MT": "MLT", "MH": "MHL", "MQ": "MTQ", "MR": "MRT", "MU": "MUS", "YT": "MYT", "MX": "MEX", "FM": "FSM", "MD": "MDA", "MC": "MCO", "MN": "MNG", "MS": "MSR", "MA": "MAR", "MZ": "MOZ", "MM": "MMR", "NA": "NAM", "NR": "NRU", "NP": "NPL", "AN": "ANT", "NL": "NLD", "NC": "NCL", "NZ": "NZL", "NI": "NIC", "NE": "NER", "NG": "NGA", "NU": "NIU", "NF": "NFK", "MP": "MNP", "NO": "NOR", "OM": "OMN", "PK": "PAK", "PW": "PLW", "PS": "PSE", "PA": "PAN", "PG": "PNG", "PY": "PRY", "PE": "PER", "PH": "PHL", "PN": "PCN", "PL": "POL", "PT": "PRT", "PR": "PRI", "QA": "QAT", "RE": "REU", "RO": "ROU", "RU": "RUS", "RW": "RWA", "SH": "SHN", "KN": "KNA", "LC": "LCA", "PM": "SPM", "VC": "VCT", "WS": "WSM", "SM": "SMR", "ST": "STP", "SA": "SAU", "SN": "SEN", "CS": "SCG", "SC": "SYC", "SL": "SLE", "SG": "SGP", "SK": "SVK", "SI": "SVN", "SB": "SLB", "SO": "SOM", "ZA": "ZAF", "GS": "SGS", "ES": "ESP", "LK": "LKA", "SD": "SDN", "SR": "SUR", "SJ": "SJM", "SZ": "SWZ", "SE": "SWE", "CH": "CHE", "SY": "SYR", "TW": "TWN", "TJ": "TJK", "TZ": "TZA", "TH": "THA", "TL": "TLS", "TG": "TGO", "TK": "TKL", "TO": "TON", "TT": "TTO", "TN": "TUN", "TR": "TUR", "TM": "TKM", "TC": "TCA", "TV": "TUV", "VI": "VIR", "UG": "UGA", "UA": "UKR", "AE": "ARE", "GB": "GBR", "UM": "UMI", "US": "USA", "UY": "URY", "UZ": "UZB", "VU": "VUT", "VE": "VEN", "VN": "VNM", "WF": "WLF", "EH": "ESH", "YE": "YEM", "ZM": "ZMB", "ZW": "ZWE",
};
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
		type: 'time.area',
		axes: ['right', 'bottom'],
		ticks: { right: 2 },
		margins: { right: 60 },
		tickFormats: {
			right: function(d) {
				if (d < 1000) {
					return d + ' pps';
				} else {
					return (d / 1000.0).toFixed(1) + ' Kpps';
				}
			},
			bottom: function(d) { return new Date(d).toTimeString().split(' ')[0]; },
		},
		data: statsHistory
	});
	var statsPrev = null;
	/* Map colour brackets. */
	var colours = [
		'#F5F5F5',
		'rgb(198,219,239)',
		'rgb(158,202,225)',
		'rgb(107,174,214)',
		'rgb(66,146,198)',
		'rgb(33,113,181)',
		'rgb(8,81,156)',
		'rgb(8,48,107)',
	];
	var fills = { defaultFill: '#F5F5F5' };
	for (var i in colours) {
		fills['q' + i] = colours[i];
	}
	var map = new Datamap({
		element: document.getElementById('map'),
		fills: fills,
		data: {},
		geographyConfig: {
			popupTemplate: function(geo, data) {
				return ['<div class="hoverinfo">',
					'<strong>', geo.properties.name, '</strong>',
					'<br>Queries: <strong>', data ? data.queries : '0', '</strong>',
					'</div>'].join('');
			}
		}
	});
	/* Draw map legend */
	var legendBarWidth = 30, legendBarHeight = 10, legendOffset = 150;
	d3.select('#map svg').append('g').attr('class', 'map-legend');
	d3.select('.map-legend').selectAll('.map-legend')
		.data(colours).enter()
		.append('rect')
			.attr('y', function(d,i) { return legendOffset + legendBarHeight*i; })
			.attr('width', legendBarWidth)
			.attr('height', legendBarHeight)
			.attr('fill', function(d){ return d; });
	/* Realtime updates */ 
	function poller(feed, interval, cb) {
		var func = function() {
			$.ajax({
				url: feed,
				type: 'get',
				dataType: 'json',
				success: cb
			});
		}
		setInterval(func, interval);
		func();
	}
	poller('stats', 1000, function(resp) {
		var now = Date.now();
		var next = [];
		for (i = 0; i < statsLabels.length; ++i) {
			next.push(resp['answer.' + statsLabels[i]]);
		}
		if (statsPrev) {
			var delta = [];
			for (i = 0; i < statsLabels.length; ++i) {
				delta.push({time: now, y: next[i]-statsPrev[i]});
			}
			statsChart.push(delta);
		}
		statsPrev = next;
	});
	poller('feed', 2000, function(resp) {
		var feed = $('#feed');
		feed.children().remove();
		feed.append('<tr><th>Type</th><th>Query</th><th>Nameserver</th><th>DNSSEC</th></tr>')
		for (i = 0; i < resp.length; ++i) {
			if (resp[i].Qname != "") {
				var row = $('<tr />');
				row.append('<td>' + resp[i].Qtype + '</td>');
				row.append('<td>' + resp[i].Qname + '</td>');
				row.append('<td>' + resp[i].Addr + '</td>');
				if (resp[i].Secure) {
					row.append('<td class="secure">SECURE</td>');
				} else {
					row.append('<td></td>');
				}
				feed.append(row);
			}
		}
	});
	poller('geo', 2000, function(resp) {
		var min = 0.0, max = 0.0;
		/* Calculate dataset limits. */
		for (var key in resp) {
			if (resp.hasOwnProperty(key)) {
				min = Math.min(min, resp[key]);
				max = Math.max(max, resp[key]);
			}
		}
		/* Map frequency to palette. */
		var dataset = {};
		var quantize = d3.scale.quantize()
			.domain([min, max])
			.range(d3.range(colours.length).map(function(i) { return "q" + i; }));
		for (var key in resp) {
			if (resp.hasOwnProperty(key)) {
				var iso3_key = iso2_to_iso3[key];
				if (iso3_key) {
					var val = resp[key];
					dataset[iso3_key] = { queries: val, fillColor: quantize(val) };
				}
			}
		}
		map.updateChoropleth(dataset);
		/* Update legend */
		d3.select('.map-legend').selectAll('text').remove();
		d3.select('.map-legend').selectAll('.map-legend')
			.data(colours).enter()
			.append('text')
				.text(function(d, i) {
					var quantizedRange = quantize.invertExtent('q' + i);
					return parseInt(quantizedRange[0]) + ' - ' + parseInt(quantizedRange[1]);
				})
				.attr('x', (legendBarWidth*1.25))
				.attr('y', function(d, i){
					return legendOffset + (legendBarHeight*0.9) + legendBarHeight*i;
				})
	});
}
