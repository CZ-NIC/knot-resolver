<!DOCTYPE html>
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<script type="text/javascript">
	var host = "{{ host }}";
</script>
<script src="jquery.js"></script>
<script src="bootstrap.min.js"></script>
<script src="d3.js"></script>
<script src="dygraph.min.js"></script>
<script src="selectize.min.js"></script>
<script src="topojson.js"></script>
<script src="datamaps.world.min.js"></script>
<script src="kresd.js"></script>
<link rel="icon" type="image/ico" href="favicon.ico">
<link href="kresd.css" rel="stylesheet">
<link href="bootstrap.min.css" rel="stylesheet">
<link href="selectize.bootstrap3.css" rel="stylesheet">
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
		<div class="col-md-12">
			<div class="row">
				<div id="stats" class="row placeholders">
					<div id="chart" style="width:100%"></div>
				</div>
			</div>
			<div class="row">
				<div class="col-md-12">
					<h3><small>More metrics</small></h3>
					<div class="col-md-11">
						<select id="chart-selector" multiple></select>
					</div>
					<div class="col-md-1">
						<div class="checkbox">
							<label><input id="chart-stacked" type="checkbox">Stacked</label>
						</div>
					</div>
				</div>
			</div>
			<div class="row">
				<h3>Instances</h3>
				<div class="col-md-12">
				<table id="workers" class="table table-responsive">
					<tr>
						<th>PID</th><th>CPU per-worker (user/sys)</th>
						<th>RSS</th><th>Page faults</th><th>Status</th>
					</tr>
				</table>
				</div>
			</div>
		</div>
		<div class="row" id="map-container">
			<a name="worldmap"></a>
			<h2 class="sub-header">Outbound queries</h2>
			<div class="col-md-12">
				<div id="map" style="position: relative;"></div>
			</div>
		</div>
		<div class="col-md-12">
			{{ snippets }}
		</div>
	</div>
</div>
