local ffi = require("ffi")

-- FIXME remove absolute path
-- the load opens the file relative to CWD. That could be anywhere. So we need to know, where is knot installed.
local clib = ffi.load("/tmp/kr/lib/knot-resolver/kres_modules/sysrepo-lua/cbindings.so")

-------------------------------------------------------------------------------
--                      FFI initialization
-------------------------------------------------------------------------------

local function initialize_ffi()
    --- Definition of `sr_val_t` copied from sysrepo.h on 2020-01-01.
    ffi.cdef[[
    /**
     * @brief Possible types of a data element stored in the sysrepo datastore.
     */
     typedef enum sr_type_e {
        /* special types that does not contain any data */
        SR_UNKNOWN_T,              /**< Element unknown to sysrepo (unsupported element). */

        SR_LIST_T,                 /**< List instance. ([RFC 7950 sec 7.8](http://tools.ietf.org/html/rfc7950#section-7.8)) */
        SR_CONTAINER_T,            /**< Non-presence container. ([RFC 7950 sec 7.5](http://tools.ietf.org/html/rfc7950#section-7.5)) */
        SR_CONTAINER_PRESENCE_T,   /**< Presence container. ([RFC 7950 sec 7.5.1](http://tools.ietf.org/html/rfc7950#section-7.5.1)) */
        SR_LEAF_EMPTY_T,           /**< A leaf that does not hold any value ([RFC 7950 sec 9.11](http://tools.ietf.org/html/rfc7950#section-9.11)) */
        SR_NOTIFICATION_T,         /**< Notification instance ([RFC 7095 sec 7.16](https://tools.ietf.org/html/rfc7950#section-7.16)) */

        /* types containing some data */
        SR_BINARY_T,       /**< Base64-encoded binary data ([RFC 7950 sec 9.8](http://tools.ietf.org/html/rfc7950#section-9.8)) */
        SR_BITS_T,         /**< A set of bits or flags ([RFC 7950 sec 9.7](http://tools.ietf.org/html/rfc7950#section-9.7)) */
        SR_BOOL_T,         /**< A boolean value ([RFC 7950 sec 9.5](http://tools.ietf.org/html/rfc7950#section-9.5)) */
        SR_DECIMAL64_T,    /**< 64-bit signed decimal number ([RFC 7950 sec 9.3](http://tools.ietf.org/html/rfc7950#section-9.3)) */
        SR_ENUM_T,         /**< A string from enumerated strings list ([RFC 7950 sec 9.6](http://tools.ietf.org/html/rfc7950#section-9.6)) */
        SR_IDENTITYREF_T,  /**< A reference to an abstract identity ([RFC 7950 sec 9.10](http://tools.ietf.org/html/rfc7950#section-9.10)) */
        SR_INSTANCEID_T,   /**< References a data tree node ([RFC 7950 sec 9.13](http://tools.ietf.org/html/rfc7950#section-9.13)) */
        SR_INT8_T,         /**< 8-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        SR_INT16_T,        /**< 16-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        SR_INT32_T,        /**< 32-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        SR_INT64_T,        /**< 64-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        SR_STRING_T,       /**< Human-readable string ([RFC 7950 sec 9.4](http://tools.ietf.org/html/rfc7950#section-9.4)) */
        SR_UINT8_T,        /**< 8-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        SR_UINT16_T,       /**< 16-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        SR_UINT32_T,       /**< 32-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        SR_UINT64_T,       /**< 64-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        SR_ANYXML_T,       /**< Unknown chunk of XML ([RFC 7950 sec 7.10](https://tools.ietf.org/html/rfc7950#section-7.10)) */
        SR_ANYDATA_T,      /**< Unknown set of nodes, encoded in XML ([RFC 7950 sec 7.10](https://tools.ietf.org/html/rfc7950#section-7.10)) */
    } sr_type_t;

    /**
     * @brief Data of an element (if applicable), properly set according to the type.
     */
    typedef union sr_data_u {
        char *binary_val;       /**< Base64-encoded binary data ([RFC 7950 sec 9.8](http://tools.ietf.org/html/rfc7950#section-9.8)) */
        char *bits_val;         /**< A set of bits or flags ([RFC 7950 sec 9.7](http://tools.ietf.org/html/rfc7950#section-9.7)) */
        bool bool_val;          /**< A boolean value ([RFC 7950 sec 9.5](http://tools.ietf.org/html/rfc7950#section-9.5)) */
        double decimal64_val;   /**< 64-bit signed decimal number ([RFC 7950 sec 9.3](http://tools.ietf.org/html/rfc7950#section-9.3)) */
        char *enum_val;         /**< A string from enumerated strings list ([RFC 7950 sec 9.6](http://tools.ietf.org/html/rfc7950#section-9.6)) */
        char *identityref_val;  /**< A reference to an abstract identity ([RFC 7950 sec 9.10](http://tools.ietf.org/html/rfc7950#section-9.10)) */
        char *instanceid_val;   /**< References a data tree node ([RFC 7950 sec 9.13](http://tools.ietf.org/html/rfc7950#section-9.13)) */
        int8_t int8_val;        /**< 8-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        int16_t int16_val;      /**< 16-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        int32_t int32_val;      /**< 32-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        int64_t int64_val;      /**< 64-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        char *string_val;       /**< Human-readable string ([RFC 7950 sec 9.4](http://tools.ietf.org/html/rfc7950#section-9.4)) */
        uint8_t uint8_val;      /**< 8-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        uint16_t uint16_val;    /**< 16-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        uint32_t uint32_val;    /**< 32-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        uint64_t uint64_val;    /**< 64-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
        char *anyxml_val;       /**< Unknown chunk of XML ([RFC 7950 sec 7.10](https://tools.ietf.org/html/rfc7950#section-7.10)) */
        char *anydata_val;      /**< Unknown set of nodes, encoded in XML ([RFC 7950 sec 7.10](https://tools.ietf.org/html/rfc7950#section-7.10)) */
    } sr_data_t;

    /**
     * @brief Structure that contains value of an data element stored in the sysrepo datastore.
     */
    typedef struct sr_val_s {
        /** [XPath](@ref paths) (or rather path) identifier of the data element. */
        char *xpath;

        /** Type of an element. */
        sr_type_t type;

        /**
         * Flag for node with default value (applicable only for leaves).
         * It is set to TRUE only if the value was *implicitly* set by the datastore as per
         * module schema. Explicitly set/modified data element (through the sysrepo API) always
         * has this flag unset regardless of the entered value.
         */
        bool dflt;

        /** [Origin](@ref oper_ds) of the value. */
        char *origin;

        /** Data of an element (if applicable), properly set according to the type. */
        sr_data_t data;

    } sr_val_t;

    typedef void (*set_leaf_conf_t)(sr_val_t *val);
    int sysrepo_init(set_leaf_conf_t set_leaf_conf_cb);
    int sysrepo_deinit(void);
    ]]
end

-- make sure this module runs just once
-- LuaJIT's FFI can't be initialized multiple times for the same types
if (_KNOT_SYSREPO_FFI_INITIALIZED == true) then
    -- nothing to initialize then
else
    initialize_ffi()
    _KNOT_SYSREPO_FFI_INITIALIZED = true
end

-- TODO version check so that we cant load new module into an old Knot

-------------------------------------------------------------------------------
--                      Data convertsion helpers
-------------------------------------------------------------------------------

--- Helper table for converting sr_data_t union type to string based on the provided type
local _value_to_str_conversion_table = {
    ["SR_UNKNOWN_T"] = function(_) return "unknown value" end,
    ["SR_LIST_T"] = function(_) return "no value (list)" end,
    ["SR_CONTAINER_T"] = function(_) return "no value (container)" end,
    ["SR_CONTAINER_PRESENCE_T"] = function(_) return "container (container presence)" end,
    ["SR_LEAF_EMPTY_T"] = function(_) return "empty (empty leaf)" end,
    ["SR_NOTIFICATION_T"] = function(_) return "no value (notification)" end,
    ["SR_BINARY_T"] = function(val) return ffi.string(val.binary_val) .. " (binary)" end,
    ["SR_BITS_T"] = function(_) return "??? (bits)" end,
    ["SR_BOOL_T"] = function(val) return tostring(val.bool_val) .. " (bool)" end,
    ["SR_DECIMAL64_T"] = function(val) return tostring(val.decimal64_val) .. "(decimal64)" end,
    ["SR_ENUM_T"] = function(val) return ffi.string(val.enum_val) .. " (enum)" end,
    ["SR_IDENTITYREF_T"] = function(val) return ffi.string(val.enum_val) .. " (indentityref)" end,
    ["SR_INSTANCEID_T"] = function(val) return ffi.string(val.enum_val) .. " (instanceid)" end,
    ["SR_INT8_T"] = function(val) return tostring(val.int8_val) .. " (int8)" end,
    ["SR_INT16_T"] = function(val) return tostring(val.int16_val) .. " (int16)" end,
    ["SR_INT32_T"] = function(val) return tostring(val.int32_val) .. " (int32)" end,
    ["SR_INT64_T"] = function(val) return tostring(val.int64_val) .. " (int64)" end,
    ["SR_STRING_T"] = function(val) return ffi.string(val.string_val) .. " (string)" end,
    ["SR_UINT8_T"] = function(val) return tostring(val.uint8_val) .. " (int8)" end,
    ["SR_UINT16_T"] = function(val) return tostring(val.uint16_val) .. " (uint16)" end,
    ["SR_UINT32_T"] = function(val) return tostring(val.uint32_val) .. " (uint32)" end,
    ["SR_UINT64_T"] = function(val) return tostring(val.uint64_val) .. " (uint64)" end,
    ["SR_ANYXML_T"] = function(val) return ffi.string(val.anyxml_val) .. " (anyxml)" end,
    ["SR_ANYDATA_T"] = function(val) return ffi.string(val.anydata_val) .. " (anydata)" end,
}

--- Convert from type sr_type_t into a uppercase string.
-- @param sr_type_t value. In case of wrong type, the function crashes the whole runtime.
-- @return string value of the enum
local function type_to_str(tp)
    if (tp == "SR_UNKNOWN_T") then return "SR_UNKNOWN_T"
    elseif (tp == "SR_LIST_T") then return "SR_LIST_T"
    elseif (tp == "SR_CONTAINER_T") then return "SR_CONTAINER_T"
    elseif (tp == "SR_CONTAINER_PRESENCE_T") then return "SR_CONTAINER_PRESENCE_T"
    elseif (tp == "SR_LEAF_EMPTY_T") then return "SR_LEAF_EMPTY_T"
    elseif (tp == "SR_NOTIFICATION_T") then return "SR_NOTIFICATION_T"
    elseif (tp == "SR_BINARY_T") then return "SR_BINARY_T"
    elseif (tp == "SR_BITS_T") then return "SR_BITS_T"
    elseif (tp == "SR_BOOL_T") then return "SR_BOOL_T"
    elseif (tp == "SR_DECIMAL64_T") then return "SR_DECIMAL64_T"
    elseif (tp == "SR_ENUM_T") then return "SR_ENUM_T"
    elseif (tp == "SR_IDENTITYREF_T") then return "SR_IDENTITYREF_T"
    elseif (tp == "SR_INSTANCEID_T") then return "SR_INSTANCEID_T"
    elseif (tp == "SR_INT8_T") then return "SR_INT8_T"
    elseif (tp == "SR_INT16_T") then return "SR_INT16_T"
    elseif (tp == "SR_INT32_T") then return "SR_INT32_T"
    elseif (tp == "SR_INT64_T") then return "SR_INT64_T"
    elseif (tp == "SR_STRING_T") then return "SR_STRING_T"
    elseif (tp == "SR_UINT8_T") then return "SR_UINT8_T"
    elseif (tp == "SR_UINT16_T") then return "SR_UINT16_T"
    elseif (tp == "SR_UINT32_T") then return "SR_UINT32_T"
    elseif (tp == "SR_UINT64_T") then return "SR_UINT64_T"
    elseif (tp == "SR_ANYXML_T") then return "SR_ANYXML_T"
    elseif (tp == "SR_ANYDATA_T") then return "SR_ANYDATA_T"
    else
        error("unexpected value of sr_type_t enum")
    end
end


-------------------------------------------------------------------------------
--                      Callback management
-------------------------------------------------------------------------------

local callbacks = {}
local function create_callback(ctype ,func)
    assert(type(ctype) == "string")
    assert(type(func) == "function")

    local cb = ffi.cast(ctype, func)
    table.insert(callbacks, cb)
    return cb
end

local function free_callbacks()
    for _, cb in ipairs(callbacks) do
        cb:free()
    end
end


-------------------------------------------------------------------------------
--                      Exported functionality
-------------------------------------------------------------------------------

local sysrepo_ffi = {}

function sysrepo_ffi.init(apply_conf_func)
    local cb = create_callback("set_leaf_conf_t", apply_conf_func)
    local res = clib.sysrepo_init(cb)
    if res ~= 0 then
        error("Initialization failed with error code " .. tostring(res))
    end
end

function sysrepo_ffi.deinit()
    local res = clib.sysrepo_deinit()
    free_callbacks()
    if res ~= 0 then
        error("Deinitialization failed with error code " .. tostring(res))
    end
end

--- Converts from cdata sr_val_t to table (using table is slower, but safer)
function sysrepo_ffi.sr_val_to_table(val)
    local tbl = {
        dflt = val.dflt,
        xpath = ffi.string(val.xpath),
        type = type_to_str(val.type),
        _value = val.data,
    }
    setmetatable(tbl, {
        __tostring = function(slf)
            return string.format(
                "{\n\txpath = '%s',\n\ttype = '%s',\n\tdflt = '%s',\n\tdata = '%s'\n}",
                slf.xpath,
                slf.type,
                tostring(slf.dflt),
                _value_to_str_conversion_table[type_to_str(slf.type)](slf._value)
            )
        end
    })
    return tbl
end

return sysrepo_ffi
