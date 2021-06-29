-- SPDX-License-Identifier: GPL-3.0-or-later
--[[
	Conventions:
		- key = private+public key-pair in openssl.pkey format
		- certs = lua list of certificates (at least one), each in openssl.x509 format,
			ordered from leaf to almost-root
		- panic('...') is used on bad problems instead of returning nils or such
--]]
local tls_cert = {}

local x509, pkey = require('openssl.x509'), require('openssl.pkey')

-- @function Create self-signed certificate; return certs, key
local function new_ephemeral(host)
	-- Import luaossl directly
	local name = require('openssl.x509.name')
	local altname = require('openssl.x509.altname')
	local openssl_bignum = require('openssl.bignum')
	local openssl_rand = require('openssl.rand')
	-- Create self-signed certificate
	host = host or hostname()
	local crt = x509.new()
	local now = os.time()
	crt:setVersion(3)
	-- serial needs to be unique or browsers will show uninformative error messages
	crt:setSerial(openssl_bignum.fromBinary(openssl_rand.bytes(16)))
	-- use the host we're listening on as canonical name
	local dn = name.new()
	dn:add("CN", host)
	crt:setSubject(dn)
	crt:setIssuer(dn) -- should match subject for a self-signed
	local alt = altname.new()
	alt:add("DNS", host)
	crt:setSubjectAlt(alt)
	-- Valid for 90 days
	crt:setLifetime(now, now + 90*60*60*24)
	-- Can't be used as a CA
	crt:setBasicConstraints{CA=false}
	crt:setBasicConstraintsCritical(true)
	-- Create and set key (default: EC/P-256 as a most "interoperable")
	local key = pkey.new {type = 'EC', curve = 'prime256v1'}
	crt:setPublicKey(key)
	crt:sign(key)
	return { crt }, key
end

-- @function Write certs and key to files
local function write_cert_files(certs, key, certfile, keyfile)
	-- Write certs
	local f = assert(io.open(certfile, 'w'), string.format('cannot open "%s" for writing', certfile))
	for _, cert in ipairs(certs) do
		f:write(tostring(cert))
	end
	f:close()
	-- Write key as a pair
	f = assert(io.open(keyfile, 'w'), string.format('cannot open "%s" for writing', keyfile))
	local pub, priv = key:toPEM('public', 'private')
	assert(f:write(pub .. priv))
	f:close()
end

-- @function Start maintenance of a self-signed TLS context (at ephem_state.ctx).
-- Keep updating the ephem_state.servers table.  Stop updating by calling _destroy().
-- TODO: each process maintains its own ephemeral cert ATM, and the files aren't ever read from.
function tls_cert.ephemeral_state_maintain(ephem_state, certfile, keyfile)
	local certs, key = new_ephemeral()
	write_cert_files(certs, key, certfile, keyfile)
	ephem_state.ctx = tls_cert.new_tls_context(certs, key)
	-- Each server needs to have its ctx updated.
	for _, s in pairs(ephem_state.servers) do
		s.server.ctx = ephem_state.ctx
		s.config.ctx = ephem_state.ctx -- not required, but let's keep it synchonized
	end
	log_info(ffi.C.DOH, 'created new ephemeral TLS certificate')
	local _, expiry_stamp = certs[1]:getLifetime()
	local wait_msec = 1000 * math.max(1, expiry_stamp - os.time() - 3 * 24 * 3600)
	if not ephem_state.timer_id then
		ephem_state.timer_id = event.after(wait_msec, function ()
			tls_cert.ephemeral_state_maintain(ephem_state, certfile, keyfile)
		end)
	else
		event.reschedule(ephem_state.timer_id, wait_msec)
	end
end
function tls_cert.ephemeral_state_destroy(ephem_state)
	if ephem_state and ephem_state.timer_id then
		event.cancel(ephem_state.timer_id)
	end
end

-- @function Read a certificate chain and a key from files; return certs, key
function tls_cert.load(certfile, keyfile)
	-- get key
	local f, err = io.open(keyfile, 'r')
	if not f then
		panic('[http] unable to open TLS key file: %s', err)
	end
	local key = pkey.new(f:read('*all'))
	f:close()
	if not key then
		panic('[http] unable to parse TLS key file %s', keyfile)
	end

	-- get certs list
	local certs = {}
	local f, err = io.open(certfile, 'r')
	if not f then
		panic('[http] unable to read TLS certificate file: %s', err)
	end
	while true do
		-- Get the next "block" = single certificate as PEM string.
		local block = nil
		local line
		repeat
			line = f:read()
			if not line then break end
			if block then
				block = block .. '\n' .. line
			else
				block = line
			end
			-- separator: "posteb" in https://tools.ietf.org/html/rfc7468#section-3
		until string.sub(line, 1, 9) == '-----END '
		-- Empty block means clean EOF.
		if not block then break end
		if not line then
			panic('[http] unable to parse TLS certificate file %s, certificate number %d', certfile, 1 + #certs)
		end

		-- Parse the cert and append to the list.
		local cert = x509.new(block, 'PEM')
		if not cert then
			panic('[http] unable to parse TLS certificate file %s, certificate number %d', certfile, 1 + #certs)
		end
		table.insert(certs, cert)
	end
	f:close()

	return certs, key
end


-- @function Prefer HTTP/2 or HTTP/1.1
local function alpnselect(_, protos)
	for _, proto in ipairs(protos) do
		if proto == 'h2' or proto == 'http/1.1' then
			return proto
		end
	end
	return nil
end

local warned_old_luaossl = false

-- @function Return a new TLS context for a server.
function tls_cert.new_tls_context(certs, key)
	local ctx = require('http.tls').new_server_context()
	if ctx.setAlpnSelect then
		ctx:setAlpnSelect(alpnselect)
	end
	assert(ctx:setPrivateKey(key))
	assert(ctx:setCertificate(certs[1]))

	-- Set up certificate chain to be sent, if required and possible.
	if #certs == 1 then return ctx end
	if ctx.setCertificateChain then
		local chain = require('openssl.x509.chain').new()
		assert(chain)
		for i = 2, #certs do
			chain:add(certs[i])
			assert(chain)
		end
		assert(ctx:setCertificateChain(chain))
	elseif not warned_old_luaossl then
		-- old luaossl version -> only final cert sent to clients
		log_warn(ffi.C.DOH, 'Warning: need luaossl >= 20181207 to support sending intermediary certificate to clients')
		warned_old_luaossl = true
	end
	return ctx
end


return tls_cert

