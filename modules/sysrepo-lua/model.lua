local debug = require("kres_modules/sysrepo-lua/debug")
local ffi = require("ffi")

local Node = {}
Node.__index = Node
local _clib = nil

local Hook = {}
Hook.__index = Hook

function Hook:create(apply_pre, apply_post)
    assert(apply_pre == nil or type(apply_pre) == "function")
    assert(apply_post == nil or type(apply_post) == "function")

    local res = {}
    setmetatable(res, Hook)

    res.apply_pre = apply_pre
    res.apply_post = apply_post

    return res
end

function Hook:apply_pre(self)
    -- empty default
end

function Hook:apply_post(self)
    -- empty default
end

local EMPTY_HOOK = Hook:create()

--- Access function to the C helper library. Returns table on which C functions can be called
--- directly. When retrieving strings, you must intern them first using `ffi.string()`
local function clib()
    assert(_clib ~= nil, "Tried to use C library before it was properly initialized.")
    return _clib
end

--- Tree node for representing a vertex in configuration model tree
---
--- Nodes can be read by node:read(data_node) and written by node:write(parent_data_node)
---
--- @param name Name of the vertex for constructing XPath
--- @param apply_func Function which takes self, data node from libyang and applies the configuration to the system
--- @param read_func Function which takes self, data node from libyang and optional argument. It adds children to the
---        given node with data from the system or its argument. Returns last node it added.
function Node:create(name, apply_func, read_func, initialize_schema_func)
    assert(type(name) == "string")
    assert(type(apply_func) == 'function')
    assert(type(read_func) == 'function')
    assert(initialize_schema_func == nil or type(initialize_schema_func) == 'function')

    local handler = {}
    setmetatable(handler, Node)

    handler.apply = apply_func
    handler.serialize = read_func
    handler.name = name
    handler.module = nil -- must be filled in later by initialize_schema method

    -- default implementation
    local function schema_init(self, lys_node)
        assert(lys_node ~= nil, "Node named \'" .. self.name .. "\' does not exist in the YANG schema"
                                                            .. " (or something else happened).")
        assert(ffi.string(clib().schema_get_name(lys_node)) == self.name)
        self.module = clib().schema_get_module(lys_node)
    end
    if initialize_schema_func == nil then
        initialize_schema_func = schema_init
    end
    handler.initialize_schema = initialize_schema_func

    return handler
end

--- Tree node that just prints its name and value. Used for development.
---
--- @param name Name of the vertex for constructing XPath
--- @param ignore_value When set to true, it does not print container value when configuration changes
local function DummyLeafNode(name, ignore_value)
    local function dummy_read(self, node)
        if ignore_value then
            debug.log(
                "Dummy read on node named \"{}\", actual name \"{}\"",
                self.name,
                ffi.string(clib().node_get_name(node))
            )
        else
            debug.log(
                "Dummy read on node named \"{}\", actual name \"{}\". Contains value (as a string) \"{}\"",
                self.name,
                ffi.string(clib().node_get_name(node)),
                ffi.string(clib().node_get_value_str(node))
            )
        end
    end

    local function dummy_write(self, node, arg)
        debug.log("dummy write on node named {}, arg={}", self.name, arg)
        return nil
    end

    return Node:create(name, dummy_read, dummy_write, nil)
end

--- Node representing a container in YANG schema. Recursively calls its children.
---
--- @param name Name of the vertex for constructing XPath
--- @param container_model List of child {@link Node}s
local function ContainerNode(name, container_model, hooks)
    -- default hooks
    if hooks == nil then
        hooks = EMPTY_HOOK
    end

    -- optimize child lookup by name with table
    local child_lookup_table = {}
    for _,v in ipairs(container_model) do
        child_lookup_table[v.name] = v
    end

    --- Node's apply function
    local function handle_cont_read(self, node)
        hooks:apply_pre()

        local node_name = ffi.string(clib().node_get_name(node))
        debug.log("Reading container \"{}\"", self.name)
        assert(node_name == self.name)

        local child = clib().node_child_first(node)
        while child ~= nil do
            local nm = ffi.string(clib().node_get_name(child))
            -- our model doesn't have to be a full copy of the actual model
            -- it has to be a subset. So there might be a node that we can't
            -- find.
            if child_lookup_table[nm] ~= nil then
                child_lookup_table[nm]:apply(child)
            end

            child = clib().node_child_next(child)
        end

        hooks:apply_post()
    end

    --- Node's serialize function
    local function handle_cont_write(self, parent_node)
        local node = clib().node_new_container(parent_node, self.module, self.name)

        for _,v in ipairs(container_model) do
            _ = v:serialize(node)
        end

        return node
    end

    local function schema_init(self, lys_node)
        assert(ffi.string(clib().schema_get_name(lys_node)) == self.name)
        self.module = clib().schema_get_module(lys_node)

        local lookup = {}
        local child = clib().schema_child_first(lys_node)
        while child ~= nil do
            local nm = ffi.string(clib().schema_get_name(child))
            lookup[nm] = child
            child = clib().schema_child_next(child)
        end

        -- apply to all children
        for _,v in ipairs(container_model) do
            v:initialize_schema(lookup[v.name])
        end
    end

    return Node:create(name, handle_cont_read, handle_cont_write, schema_init)
end

--- Node used for binding values
---
--- @param name Name of the vertex for constructing XPath
--- @param type Type of the binded value as a string
--- @param get_val Function that returns value with proper type, provides current state of the resolver.
--- @param set_val Function with one argument of appropriate type, configures resolver
local function BindNode(name, type, get_val, set_val)
    --- Node's apply function
    local function handle_apply(self, node)
        -- do nothing when there is no set func
        if set_val == nil then
            return
        end

        -- obtain value from the lyd_node according to specified type
        local val = nil
        if type == "uint8" or type == "uint32" or type == "uint64" then
            val = tonumber(ffi.string(clib().node_get_value_str(node)))
        else
            assert(false, "Trying to serialize unknown type")
        end

        -- set the value
        set_val(val)
    end

    --- Node's serialize function
    local function handle_serialize(self, parent_node)
        if get_val == nil then
            return nil
        end

        return clib().node_new_leaf(parent_node, self.module, self.name, tostring(get_val()))
    end

    return Node:create(name, handle_apply, handle_serialize, nil)
end

--- Specialized {@link BindNode} which provides read only binding to a variable
---
--- @param name Name of the vertex for constructing XPath
--- @param type Type of the binded value as a string
--- @param bind_variable String name of the binded global variable
local function StateNode(name, type, bind_variable)
    -- generate get function
    local get_val = load("return " .. bind_variable)

    return BindNode(name, type, get_val, nil)
end

--- Specialized {@link BindNode} which provides read-write binding to a function
---
--- @param name Name of the vertex for constructing XPath
--- @param type Type of the binded value as a string
--- @param bind_func String name of the binded global function. When called without arguments, returns
---     current state. When called with one argument, sets value.
local function ConfigFnNode(name, type, bind_func)
    -- generate set and get functions
    local get_val = function() return bind_func() end
    local set_val = function(new_val) bind_func(new_val) end

    return BindNode(name, type, get_val, set_val)
end

--- Specialized {@link BindNode} which provides read-write binding to a variable
---
--- @param name Name of the vertex for constructing XPath
--- @param type Type of the binded value as a string
--- @param bind_value String name of the binded global variable.
local function ConfigVarNode(name, type, bind_variable)
    -- generate set and get functions
    local get_val = load("return " .. bind_variable)
    local set_val = load("return function(data) " .. bind_variable .. "= data end")()

    return BindNode(name, type, get_val, set_val)
end

local function ListenInterfacesNode()
    -- |  |  +--rw listen-interfaces* [name]
    -- |  |  |  +--rw ip-address <ip-address(union)>
    -- |  |  |  +--rw name <string>
    -- |  |  |  +--rw port? <port-number(uint16)>

    local function handle_apply(self, node)
        -- open new listen sockets

        -- create lookup table for nodes by name
        local lookup = {}
        local child = clib().node_child_first(node)
        while child ~= nil do
            local nm = ffi.string(clib().node_get_name(child))
            lookup[nm] = child
            child = clib().node_child_next(child)
        end

        local port = tonumber(ffi.string(clib().node_get_value_str(lookup["port"])))
        local ip = ffi.string(clib().node_get_value_str(lookup["ip-address"]))

        debug.log("New interface config - listen on {}:{}", ip, port)
        net.listen(ip, port)
    end

    local function handle_serialize(self, parent_node)
        local function gen_name(ip, port)
            return tostring(ip) .. ":" .. tostring(port)
        end

        local cont = nil
        for _,v in ipairs(net.list()) do
            -- handle only udp protocol, because TCP sockets mirror UDP
            if v['transport']['protocol'] == 'udp' then
                local ip = v['transport']['ip']
                local port = v['transport']['port']

                cont = clib().node_new_container(parent_node, self.module, self.name)
                clib().node_new_leaf(cont, self.module, "ip-address", ip)
                clib().node_new_leaf(cont, self.module, "name", gen_name(ip, port))
                clib().node_new_leaf(cont, self.module, "port", tostring(port))
            end
        end

        return cont -- we should return the most recently added child
    end

    return Node:create("listen-interfaces", handle_apply, handle_serialize, nil)
end

local function hook_apply_pre_network()
    debug.log("Cleaning previously created listen sockets")

    -- close all previously opened listen sockets
    local already_listening = net.list()
    for _,v in ipairs(already_listening) do
        net.close(v['transport']['ip'], v['transport']['port'])
    end
end

--- Configuration schema reprezentation
local model =
    ContainerNode("dns-resolver", {
        ContainerNode("cache", {
            StateNode("current-size", "uint64", "cache.current_size"),
            BindNode("max-size", "uint64", function() return cache.current_size end, function(v) cache.size = v end),
            ConfigFnNode("max-ttl", "uint32", cache.max_ttl),
            ConfigFnNode("min-ttl", "uint32", cache.min_ttl),
        }),
        ContainerNode("logging", {
            BindNode("verbosity", "uint8", function() return verbose() and 1 or 0 end, function(v) verbose(v > 0) end)
        }),
        ContainerNode("network", {
            ListenInterfacesNode(),
        }, Hook:create(hook_apply_pre_network, nil)),
    })

--- Module constructor
return function(clib_binding)
    _clib = clib_binding

    local initialized_schema = false
    local function init_schema()
        if not initialized_schema then
            model:initialize_schema(clib().schema_root())
            initialized_schema = true
        end
    end

    local module = {}
    function module.serialize_configuration(root_node)
        init_schema()

        -- serialize operational data
        local node = model:serialize(root_node)
        assert(node ~= nil)

        -- validate the result
        local validation_result = clib().node_validate(node)
        if validation_result ~= 0 then
            clib().node_free(node)
            print("Tree validation failed, see printed libyang errors")
            node = nil
        end

        return node
    end

    function module.apply_configuration(root_node)
        init_schema()
        model:apply(root_node)
    end

    return module
end

