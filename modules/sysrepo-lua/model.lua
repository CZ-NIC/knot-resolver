local debug = require("kres_modules/sysrepo-lua/debug")
local ffi = require("ffi")

local Node = {}
Node.__index = Node

local _clib = nil
local function clib()
    assert(_clib ~= nil)
    return _clib
end

--- Tree node for representing a vertex in configuration model tree
---
--- Nodes can be read by node:read(data_node) and written by node:write(parent_data_node)
---
--- @param name Name of the vertex for constructing XPath
--- @param apply_func Function which takes self and data node from libyang and applies the configuration to the system
--- @param read_func Function which takes self and data node from libyang and adds a child to it with data from
---        the system. Returns a node it added.
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
        assert(ffi.string(clib().schema_get_name(lys_node)) == self.name)
        self.module = clib().schema_get_module(lys_node)
    end
    if initialize_schema_func == nil then
        initialize_schema_func = schema_init
    end
    handler.initialize_schema = initialize_schema_func

    return handler
end

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

    local function dummy_write(self, node)
        debug.log("dummy write on node named {}", self.name)
        return nil
    end

    return Node:create(name, dummy_read, dummy_write, nil)
end

local function ContainerNode(name, container_model)
    -- optimize child lookup by name with table
    local child_lookup_table = {}
    for _,v in ipairs(container_model) do
        child_lookup_table[v.name] = v
    end

    --- Node's apply function
    local function handle_cont_read(self, node)
        local node_name = ffi.string(clib().node_get_name(node))
        debug.log("Attempting to read container \"{}\", it's actual name is \"{}\"", self.name, node_name)
        assert(node_name == self.name)

        local child = clib().node_child_first(node)
        while child ~= nil do
            local nm = ffi.string(clib().node_get_name(child))
            child_lookup_table[nm]:apply(child)
            child = clib().node_child_next(child)
        end
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

local function BindNode(name, type, get_val, set_val)
    --- Node's apply function
    local function handle_apply(self, node)
        -- do nothing when there is no set func
        if set_val == nil then
            return
        end

        local val = nil
        if type == "uint32" or type == "uint64" then
            val = tonumber(ffi.string(clib().node_get_value_str(node)))
        else
            assert(false, "Trying to serialize unknown type")
        end
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

local function StateNode(name, type, bind_variable)
    -- generate get function
    local get_val = load("return " .. bind_variable)

    return BindNode(name, type, get_val, nil)
end

local function ConfigFnNode(name, type, bind_variable)
    -- generate set and get functions
    local get_val = load("return " .. bind_variable .. "()")
    local set_val = load("return function(data) " .. bind_variable .. "(data) end")()

    return BindNode(name, type, get_val, set_val)
end


--- Configuration schema reprezentation
local model =
    ContainerNode("dns-resolver", {
        ContainerNode("cache", {
            StateNode("current-size", "uint64", "cache.current_size"),
            DummyLeafNode("max-size"),
            ConfigFnNode("max-ttl", "uint32", "cache.max_ttl"),
            ConfigFnNode("min-ttl", "uint32", "cache.min_ttl"),
        }),
        DummyLeafNode("debugging", true),
        DummyLeafNode("dns64", true),
        DummyLeafNode("dnssec", true),
        DummyLeafNode("garbage-collector", true),
        DummyLeafNode("logging", true),
        DummyLeafNode("network", true),
        DummyLeafNode("resolver", true),
        DummyLeafNode("server", true),
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

