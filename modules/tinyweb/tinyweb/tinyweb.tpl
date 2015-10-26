<!DOCTYPE html>
<title>{{.Title}}</title>
<style>
	body { font-family: 'Gill Sans', 'Gill Sans MT', Verdana, sans-serif; color: #555; }
	h1, h2, h3 { line-height: 2em; color: #000; text-align: center; border-bottom: 1px solid #ccc; }
	h1, h2, h3 { font-weight: 300; }
	th { text-align: left; font-weight: normal; margin-bottom: 0.5em; }
	#page { font-weight: 300; }
	#page { width: 800px; margin: 0 auto; }
	#stats, #map { width: 800px; height: 300px; }
	#stats .layer-cached .area, .l-cached  { fill: #2CA02C; color: #2CA02C; }
	#stats .layer-10ms .area  , .l-10ms    { fill: #165683; color: #165683; }
	#stats .layer-100ms .area , .l-100ms   { fill: #258FDA; color: #258FDA; }
	#stats .layer-1000ms .area, .l-1000ms  { fill: #51A5E1; color: #51A5E1; }
	#stats .layer-slow .area  , .l-slow    { fill: #E1AC51; color: #E1AC51; }
	#feed { width: 100%; }
	#feed .secure { color: #74c476; }
	.stats-legend { text-align: center; }
	.stats-legend li { display: inline; list-style-type: none; padding-right: 20px; }
	.map-legend { font-size: 10px; }
</style>
<script type="text/javascript" src="jquery.js"></script>
<script type="text/javascript" src="d3.js"></script>
<script type="text/javascript" src="epoch.js"></script>
<script type="text/javascript" src="topojson.js"></script>
<script type="text/javascript" src="datamaps.world.min.js"></script>
<script type="text/javascript" src="tinyweb.js"></script>
<link rel="stylesheet" type="text/css" href="epoch.css">
<div id="page">
	<h1>{{.Title}}</h1>
	<div class="epoch" id="stats"></div>
	<ul class="stats-legend"></ul>
	<h2>Queried servers</h2>
	<div id="map" style="position: relative;"></div>
	<h2>Last queries</h2>
	<table id="feed"></table>
</div>
