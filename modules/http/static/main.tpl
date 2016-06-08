<!DOCTYPE html>
<meta charset="utf-8">
<title>{{ title }}</title>
<style>
	body { font-family: 'Gill Sans', 'Gill Sans MT', Verdana, sans-serif; color: #555; }
	h1, h2 { line-height: 1.5em; text-align: center; border-bottom: 1px solid #ccc; }
	h1, h2, h3 { color: #000; font-weight: 300; }
	th { text-align: left; font-weight: normal; margin-bottom: 0.5em; }
	#page { font-weight: 300; }
	#page { width: 900px; margin: 0 auto; }
	#stats { height: 350px; display: block; }
	#chart {
		display: inline-block;
		left: 50px;
	}
	#legend {
		background-color: white;
	}
	#legend .label {
		color: #404040;
	}
	#legend .action {
		color: black;
		opacity: 0.5;
	}
	#legend ul {
		padding: 0;
	}
	#legend_container h3 {
		margin-top: 0;
	}
	#y_axis {
		position: absolute;
		width: 50px;
		height: 350px;
	}
	#legend_container {
		padding: 0;
		width: 140px;
		display: inline-block;
		vertical-align: top;
	}
	#chart_container {
		width: 760px;
		float: left;
		position: relative;
	}
	.map-legend { font-size: 10px; }
</style>
<script type="text/javascript">
	var host = "{{ host }}";
	var secure = {{ secure }};
</script>
<script type="text/javascript" src="jquery.js"></script>
<script type="text/javascript" src="d3.js"></script>
<script type="text/javascript" src="rickshaw.min.js"></script>
<script type="text/javascript" src="topojson.js"></script>
<script type="text/javascript" src="datamaps.world.min.js"></script>
<script type="text/javascript" src="kresd.js"></script>
<link rel="icon" type="image/ico" href="favicon.ico">
<link rel="stylesheet" type="text/css" href="rickshaw.min.css">
<div id="page">
	<h1>{{ title }}</h1>
	<div id="stats">
		<form id="legend_container">
			<div id="legend"></div>
		</form>
		<div id="chart_container">
			<div id="y_axis"></div>
			<div id="chart"></div>
			<div id="x_axis"></div>
		</div>
	</div>
	<h2>Where do the queries go?</h2>
	<div id="map" style="position: relative;"></div>
	{{ snippets }}
</div>
