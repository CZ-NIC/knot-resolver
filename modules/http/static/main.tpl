<!DOCTYPE html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<script type="text/javascript">
	var host = "{{ host }}";
	var secure = {{ secure }};
</script>
<script src="jquery.js"></script>
<script src="d3.js"></script>
<script src="rickshaw.min.js"></script>
<script src="topojson.js"></script>
<script src="selectize.min.js"></script>
<script src="bootstrap.min.js"></script>
<script src="datamaps.world.min.js"></script>
<script src="kresd.js"></script>
<link rel="icon" type="image/ico" href="favicon.ico">
<link href="kresd.css" rel="stylesheet">
<link href="rickshaw.min.css" rel="stylesheet">
<link href="bootstrap.min.css" rel="stylesheet">
<link href="bootstrap-theme.min.css" rel="stylesheet">
<link href="selectize.min.css" rel="stylesheet">
<link href="selectize.bootstrap3.min.css" rel="stylesheet">
<nav class="navbar navbar-inverse navbar-fixed-top">
	<div class="container">
		<div class="navbar-header">
			<button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
				<span class="sr-only">Toggle navigation</span>
				<span class="icon-bar"></span>
				<span class="icon-bar"></span>
				<span class="icon-bar"></span>
			</button>
			<a class="navbar-brand" href="#">{{ title }}</a>
		</div>
		<ul class="nav navbar-nav navbar-right">
			<li><a href="#">Metrics</a></li>
			<li><a href="#worldmap">World Map</a></li>
			<li class="dropdown">
				<a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false">Modules <span class="caret"></span></a>
				<ul class="dropdown-menu" id="modules-dropdown">
				</ul>
			</li>
		</ul>
	</div>
</nav>
<div class="container">
	<div class="main">
		<h2 class="sub-header">Metrics</h2>
		<div id="stats" class="row placeholders">
			<div id="chart_container">
				<div id="y_axis"></div>
				<div id="chart"></div>
				<div id="x_axis"></div>
			</div>
			<form id="legend_container">
				<div id="legend"></div>
			</form>
		</div>
		<a name="worldmap"></a>
		<h2 class="sub-header">Where do the queries go?</h2>
		<div id="map" style="position: relative;"></div>
		{{ snippets }}
	</div>
</div>
