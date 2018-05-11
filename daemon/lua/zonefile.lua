-- LuaJIT ffi bindings for zscanner, a DNS zone parser.
-- Author: Marek Vavrusa <marek.vavrusa@nic.cz>
-- FIXME: generate

local ffi = require('ffi')
local libzscanner = ffi.load(libzscanner_SONAME)
ffi.cdef[[
void free(void *ptr);
void *realloc(void *ptr, size_t size);

/*
 * Data structures
 */

enum {
	MAX_RDATA_LENGTH = 65535,
	MAX_ITEM_LENGTH = 255,
	MAX_DNAME_LENGTH = 255,
	MAX_LABEL_LENGTH = 63,
	MAX_RDATA_ITEMS = 64,
	BITMAP_WINDOWS = 256,
	INET4_ADDR_LENGTH = 4,
	INET6_ADDR_LENGTH = 16,
	RAGEL_STACK_SIZE = 16,
};
typedef struct {
	uint8_t bitmap[32];
	uint8_t length;
} window_t;
typedef struct {
	uint8_t  excl_flag;
	uint16_t addr_family;
	uint8_t  prefix_length;
} apl_t;
typedef struct {
	uint32_t d1, d2;
	uint32_t m1, m2;
	uint32_t s1, s2;
	uint32_t alt;
	uint64_t siz, hp, vp;
	int8_t   lat_sign, long_sign, alt_sign;
} loc_t;
typedef struct zs_state {
	static const int NONE    = 0;
	static const int DATA    = 1;
	static const int ERROR   = 2;
	static const int INCLUDE = 3;
	static const int EOF     = 4;
	static const int STOP    = 5;
} zs_state_t;

typedef struct scanner {
	int      cs;
	int      top;
	int      stack[RAGEL_STACK_SIZE];
	bool     multiline;
	uint64_t number64;
	uint64_t number64_tmp;
	uint32_t decimals;
	uint32_t decimal_counter;
	uint32_t item_length;
	uint32_t item_length_position;
	uint8_t *item_length_location;
	uint32_t buffer_length;
	uint8_t  buffer[MAX_RDATA_LENGTH];
	char     include_filename[MAX_RDATA_LENGTH];
	char     *path;
	window_t windows[BITMAP_WINDOWS];
	int16_t  last_window;
	apl_t    apl;
	loc_t    loc;
	bool     long_string;
	uint8_t  *dname;
	uint32_t *dname_length;
	uint32_t dname_tmp_length;
	uint32_t r_data_tail;
	uint32_t zone_origin_length;
	uint8_t  zone_origin[MAX_DNAME_LENGTH + MAX_LABEL_LENGTH];
	uint16_t default_class;
	uint32_t default_ttl;
	int state;
	struct {
		bool automatic;
		void (*record)(struct zs_scanner *);
		void (*error)(struct zs_scanner *);
		void *data;
	} process;
	struct {
		const char *start;
		const char *current;
		const char *end;
		bool eof;
	} input;
	struct {
		char *name;
		int  descriptor;
	} file;
	struct {
		int code;
		uint64_t counter;
		bool fatal;
	} error;
	uint64_t line_counter;
	uint32_t r_owner_length;
	uint8_t  r_owner[MAX_DNAME_LENGTH + MAX_LABEL_LENGTH];
	uint16_t r_class;
	uint32_t r_ttl;
	uint16_t r_type;
	uint32_t r_data_length;
	uint8_t  r_data[MAX_RDATA_LENGTH];
} zs_scanner_t;

/*
 * Function signatures
 */
int zs_init(zs_scanner_t *scanner, const char *origin, const uint16_t rclass, const uint32_t ttl);
void zs_deinit(zs_scanner_t *scanner);
int zs_set_input_string(zs_scanner_t *scanner, const char *input, size_t size);
int zs_set_input_file(zs_scanner_t *scanner, const char *file_name);
int zs_parse_record(zs_scanner_t *scanner);
const char* zs_strerror(const int code);
]]

-- Constant table
local zs_state = ffi.new('struct zs_state')

-- Wrap scanner context
local zs_scanner_t = ffi.typeof('struct scanner')
ffi.metatype( zs_scanner_t, {
	__gc = function(zs) return libzscanner.zs_deinit(zs) end,
	__new = function(ct, origin, class, ttl)
		if not class then class = 1 end
		if not ttl then ttl = 3600 end
		local parser = ffi.new(ct)
		libzscanner.zs_init(parser, origin, class, ttl)
		return parser
	end,
	__index = {
		open = function (zs, file)
			assert(ffi.istype(zs, zs_scanner_t))
			local ret = libzscanner.zs_set_input_file(zs, file)
			if ret ~= 0 then return false, zs:strerr() end
			return true
		end,
		parse = function(zs, input)
			assert(ffi.istype(zs, zs_scanner_t))
			if input ~= nil then libzscanner.zs_set_input_string(zs, input, #input) end
			local ret = libzscanner.zs_parse_record(zs)
			-- Return current state only when parsed correctly, otherwise return error
			if ret == 0 and zs.state ~= zs_state.ERROR then
				return zs.state == zs_state.DATA
			else
				return false, zs:strerr()
			end
		end,
		current_rr = function(zs)
			assert(ffi.istype(zs, zs_scanner_t))
			return {
				owner = ffi.string(zs.r_owner, zs.r_owner_length),
				ttl = tonumber(zs.r_ttl),
				class = tonumber(zs.r_class),
				type = tonumber(zs.r_type),
				rdata = ffi.string(zs.r_data, zs.r_data_length),
				comment = zs:current_comment(),
			}
		end,
		strerr = function(zs)
			assert(ffi.istype(zs, zs_scanner_t))
			return ffi.string(libzscanner.zs_strerror(zs.error.code))
		end,
		current_comment = function(zs)
			if zs.buffer_length > 0 then
				return ffi.string(zs.buffer, zs.buffer_length - 1)
			else
				return nil
			end
		end
	},
})

-- Module API
local rrparser = {
	new = zs_scanner_t,

	-- Parse a file into a list of RRs
	file = function (path)
		local zs = zs_scanner_t()
		local ok, err = zs:open(path)
		if not ok then
			return ok, err
		end
		local results = {}
		while zs:parse() do
			table.insert(results, zs:current_rr())
		end
		return results
	end,

	-- Parse a string into a list of RRs.
	string = function (input)
		local zs = zs_scanner_t()
		local results = {}
		local ok = zs:parse(input .. '\n') -- avoid problems with strings without newlines
										   -- TODO: it's OK since libzscanner-2.4.2
		while ok do
			table.insert(results, zs:current_rr())
			ok = zs:parse()
		end
		return results
	end,

	state = zs_state,
}
return rrparser
