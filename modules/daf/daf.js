/* Filter grammar
 * SPDX-License-Identifier: GPL-3.0-or-later */
const dafg = {
	key: {'qname': true, 'src': true, 'dst': true},
	op: {'=': true, '~': true},
	conj: {'and': true, 'or': true},
	action: {'pass': true, 'deny': true, 'drop': true, 'truncate': true, 'forward': true, 'reroute': true, 'rewrite': true, 'mirror': true},
	suggest: [
		'QNAME = example.com',
		'QNAME ~ %d+.example.com',
		'SRC = 127.0.0.1',
		'SRC = 127.0.0.1/8',
		'DST = 127.0.0.1',
		'DST = 127.0.0.1/8',
		/* Action examples */
		'PASS', 'DENY', 'DROP', 'TRUNCATE',
		'FORWARD 127.0.0.1',
		'MIRROR 127.0.0.1',
		'REROUTE 127.0.0.1-192.168.1.1',
		'REROUTE 127.0.0.1/24-192.168.1.0',
		'REWRITE example.com A 127.0.0.1',
		'REWRITE example.com AAAA ::1',
	]
};

function setValidateHint(cls) {
	var builderForm = $('#daf-builder-form');
	builderForm.removeClass('has-error has-warning has-success');
	if (cls) {
		builderForm.addClass(cls);
	}
}

function validateToken(tok, tbl) {
	if (tok.length > 0 && tok[0].length > 0) {
		if (tbl[tok[0].toLowerCase()]) {
			setValidateHint('has-success');
			return true;
		} else { setValidateHint('has-error'); }
	} else { setValidateHint('has-warning'); }
	return false;
}

function parseOption(tok) {
	var key = tok.shift().toLowerCase();
	var op = null;
	if (dafg.key[key]) {
		op = tok.shift();
		if (op) {
			op = op.toLowerCase();
		}
	}
	const item = {
		text: key.toUpperCase() + ' ' + (op ? op.toUpperCase() : '') + ' ' + tok.join(' '),
	};
	if (dafg.key[key]) {
		item.class = 'tag-default';
	} else if (dafg.action[key]) {
		item.class = 'tag-warning';
	} else if (dafg.conj[key]) {
		item.class = 'tag-success';
	}
	return item;
}

function createOption(input) {
	const item = parseOption(input.split(' '));
	item.value = input;
	return item;
}

function dafComplete(form) {
	const items = form.items;
	for (var i in items) {
		const tok = items[i].split(' ')[0].toLowerCase();
		if (dafg.action[tok]) {
			return true;
		}
	}
	return false;
}

function formatRule(input) {
	const tok = input.split(' ');
	var res = [];
	while (tok.length > 0) {
		const key = tok.shift().toLowerCase();
		if (dafg.key[key]) {
			var item = parseOption([key, tok.shift(), tok.shift()]);
			res.push('<span class="label tag '+item.class+'">'+item.text+'</span>');
		} else if (dafg.action[key]) {
			var item = parseOption([key].concat(tok));
			res.push('<span class="label tag '+item.class+'">'+item.text+'</span>');
			tok.splice(0, tok.length);
		} else if (dafg.conj[key]) {
			var item = parseOption([key]);
			res.push('<span class="label tag '+item.class+'">'+item.text+'</span>');
		}
	}
	return res.join('');
}

function toggleRule(row, span, enabled) {
	if (!enabled) {
		span.removeClass('glyphicon-pause');
		span.addClass('glyphicon-play');
		row.addClass('warning');
	} else {
		span.removeClass('glyphicon-play');
		span.addClass('glyphicon-pause');
		row.removeClass('warning');
	}
}

function ruleControl(cell, type, url, action) {
	const row = cell.parent();
	$.ajax({
		url: 'daf/' + row.data('rule-id') + url,
		type: type,
		success: action,
		fail: function (data) {
			row.show();
			const reason = data.responseText.length > 0 ? data.responseText : 'internal error';
			cell.find('.alert').remove();
			cell.append(
				'<div class="alert alert-danger" role="alert">'+
				'Failed (code: '+data.status+', reason: '+reason+').'+
				'</div>'
			);
		},
	});
}

function bindRuleControl(cell) {
	const row = cell.parent();
	cell.find('.daf-remove').click(function() {
		row.hide();
		ruleControl(cell, 'DELETE', '', function (data) {
			cell.parent().remove();
		});
	});
	cell.find('.daf-suspend').click(function() {
		const span = $(this).find('span');
		ruleControl(cell, 'PATCH', span.hasClass('glyphicon-pause') ? '/active/false' : '/active/true');
		toggleRule(row, span, span.hasClass('glyphicon-play'));
	});
}

function loadRule(rule, tbl) {
	const row = $('<tr data-rule-id="'+rule.id+'" />');
	row.append('<td class="daf-rule">' + formatRule(rule.info) + '</td>');
	row.append('<td class="daf-count">' + rule.count + '</td>');
	row.append('<td class="daf-rate"><span class="badge"></span></td>');
	row.append('<td class="daf-ctl text-right">' +
		'<div class="btn-group btn-group-xs">' +
		'<button class="btn btn-default daf-suspend"><span class="glyphicon" aria="hidden" /></button>' +
		'<button class="btn btn-default daf-remove"><span class="glyphicon glyphicon-remove" aria="hidden" /></button>' +
		'</div></td>');
	tbl.append(row);
	/* Bind rule controls */
	bindRuleControl(row.find('.daf-ctl'));
	toggleRule(row, row.find('.daf-suspend span'), rule.active);
}

/* Load the filter table from JSON */
function loadTable(resp) {
	const tbl = $('#daf-rules')
	tbl.children().remove();
	tbl.append('<tr><th>Rule</th><th>Matches</th><th>Rate</th><th></th></tr>')
	for (var i in resp) {
		loadRule(resp[i], tbl);
	}
}

$(function() {
	/* Load the filter table. */
	$.ajax({
		url: 'daf',
		type: 'get',
		dataType: 'json',
		success: loadTable
	});
	/* Listen for counter updates */
	const wsStats = (secure ? 'wss://' : 'ws://') + location.host + '/daf';
	const ws = new Socket(wsStats);
	var lastRateUpdate = Date.now();
	ws.onmessage = function(evt) {
		var data = JSON.parse(evt.data);
		/* Update heartbeat clock */
		var now = Date.now();
		var dt = now - lastRateUpdate;
		lastRateUpdate = now;
		/* Update match counts and rates */
		$('#daf-rules .daf-rate span').text('');
		for (var key in data) {
			const row = $('tr[data-rule-id="'+key+'"]');
			if (row) {
				const cell = row.find('.daf-count');
				const diff = data[key] - parseInt(cell.text());
				cell.text(data[key]);
				const badge = row.find('.daf-rate span');
				if (diff > 0) {
					/* Normalize difference to heartbeat (in msecs) */
					const rate = Math.ceil((1000 * diff) / dt);
					badge.text(rate + ' pps');
				}
			}
		}
	};
	/* Rule builder UI */
	$('#daf-builder').selectize({
		delimiter: ',',
		persist: true,
		highlight: true,
		closeAfterSelect: true,
		onItemAdd: function (input, item) {
		    setValidateHint();
		    /* Prevent new rules when action is specified */
		    const tok = input.split(' ');
		    if (dafg.action[tok[0].toLowerCase()]) {
		    	$('#daf-add').focus();
		    } else if(dafComplete(this)) {
		    	/* No more rules after query is complete. */
		    	item.remove();
		    }
		},
		createFilter: function (input) {
			const tok = input.split(' ');
			var key, op, expr;
			/* If there are already filters, allow conjunctions. */
			if (tok.length > 0 && this.items.length > 0 && dafg.conj[tok[0]]) {
				setValidateHint();
				return true;
			}
			/* First token is expected to be filter key,
			 * or any postrule with a parameter */
			if (validateToken(tok, dafg.key)) {
				key = tok.shift();
			} else if (tok.length > 1 && validateToken(tok, dafg.action)) {
				setValidateHint();
				return true;
			} else {
				return false;
			}
			/* Input is a filter - second token must be operator */
			if (validateToken(tok, dafg.op)) {
				op = tok.shift();
			} else {
				return false;
			}
			/* Input is a filter - the rest of the tokens are RHS arguments. */
			if (tok.length > 0 && tok[0].length > 0) {
				expr = tok.join(' ');
			} else {
				setValidateHint('has-warning');
				return false;
			}
			setValidateHint('has-success');
			return true;
		},
		create: createOption,
		render: {
			item: function(item, escape) {
				return '<div class="name '+item.class+'">' + escape(item.text) + '</span>';
			},
		},
	});
	/* Add default suggestions. */
	const dafBuilder = $('#daf-builder')[0].selectize;
	for (var i in dafg.suggest) {
		dafBuilder.addOption(createOption(dafg.suggest[i]));
	}
	/* Rule builder submit */
	$('#daf-add').click(function () {
		const form = $('#daf-builder-form').parent();
		if (dafBuilder.items.length == 0 || form.hasClass('has-error')) {
			return;
		}
		/* Clear previous errors and resubmit. */
		form.parent().find('.alert').remove();
		$.post('daf', dafBuilder.items.join(' '))
			.done(function (data) {
				dafBuilder.clear();
				loadRule(data, $('#daf-rules'));
			})
			.fail(function (data) {
				const reason = data.responseText.length > 0 ? data.responseText : 'internal error';
				form.after(
					'<div class="alert alert-danger" role="alert">'+
				       'Couldn\'t add rule (code: '+data.status+', reason: '+reason+').'+
				    '</div>'
				);
			});
	});
});
