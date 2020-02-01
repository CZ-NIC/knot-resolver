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
--- @param read_func Function which takes self and data node from libyang and applies the configuration to the system
--- @param write_func Function which takes self and data node from libyang and adds a child to it with data from the system
function Node:create(name, read_func, write_func)
    assert(type(name) == "string")
    assert(type(read_func) == 'function')
    assert(type(write_func) == 'function')

    local handler = {}
    setmetatable(handler, Node)

    handler.read = read_func
    handler.write = write_func
    handler.name = name

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
    end

    return Node:create(name, dummy_read, dummy_write)
end

local function ContainerNode(name, container_model)
    -- optimize child lookup by name with table
    local child_lookup_table = {}
    for _,v in ipairs(container_model) do
        child_lookup_table[v.name] = v
    end

    --- Node's read function
    local function handle_cont_read(self, node)
        local node_name = ffi.string(clib().node_get_name(node))
        debug.log("Attempting to read container \"{}\", it's actual name is \"{}\"", self.name, node_name)
        assert(node_name == self.name)

        local child = clib().node_child_first(node)
        while child ~= nil do
            local nm = ffi.string(clib().node_get_name(child))
            child_lookup_table[nm]:read(child)
            child = clib().node_child_next(child)
        end
    end

    --- Node's write function
    local function handle_cont_write(self, parent_node)
        local node = nil -- TODO get current node from parent_node

        for _,v in ipairs(container_model) do
            v:write(node)
        end
    end

    return Node:create(name, handle_cont_read, handle_cont_write)
end


--- Configuration schema reprezentation
local model = 
    ContainerNode("dns-resolver", {
        ContainerNode("cache", {
            DummyLeafNode("current-size"),
            DummyLeafNode("max-size"),
            DummyLeafNode("max-ttl"),
            DummyLeafNode("min-ttl"),
            DummyLeafNode("prefill"),
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

    local module = {}
    function module.serialize_configuration(root_node)
        model:write(root_node)
    end

    function module.apply_configuration(root_node)
        model:read(root_node)
    end

    return module
end

