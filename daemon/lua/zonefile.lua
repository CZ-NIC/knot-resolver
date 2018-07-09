-- LuaJIT ffi bindings for zscanner, a DNS zone parser.
-- Author: Marek Vavrusa <marek.vavrusa@nic.cz>
-- FIXME: generate

local ffi = require('ffi')
local libzscanner = ffi.load(libzscanner_SONAME)
-- FIXME: strip the C comments, probably
-- Note: struct zs_scanner::state uses int directly instead of typedefed enum,
-- and the corresponding struct zs_state is defined in a different way.
ffi.cdef[[
void free(void *ptr);
void *realloc(void *ptr, size_t size);

/*
 * Data structures
 */

enum {
	ZS_MAX_RDATA_LENGTH	=65535,
	ZS_MAX_DNAME_LENGTH	=255,
	ZS_MAX_LABEL_LENGTH	=63,
	ZS_INET4_ADDR_LENGTH	=4,
	ZS_INET6_ADDR_LENGTH	=16,
	ZS_BITMAP_WINDOWS	=256,
	ZS_RAGEL_STACK_SIZE	=16,
};

typedef struct {
	uint8_t bitmap[32];
	uint8_t length;
} zs_win_t;

/*! \brief Auxiliary structure for storing one APL record (see RFC3123). */
typedef struct {
	uint8_t  excl_flag;
	uint16_t addr_family;
	uint8_t  prefix_length;
} zs_apl_t;

/*! \brief Auxiliary structure for storing LOC information (see RFC1876). */
typedef struct {
	uint32_t d1, d2;
	uint32_t m1, m2;
	uint32_t s1, s2;
	uint32_t alt;
	uint64_t siz, hp, vp;
	int8_t   lat_sign, long_sign, alt_sign;
} zs_loc_t;

/*! \brief Scanner states describing the result. */
typedef struct zs_state {
	static const int NONE = 0;     /*!< Initial state (no data). */
	static const int DATA = 1;     /*!< A record parsed. */
	static const int ERROR = 2;    /*!< An error occurred. */
	static const int INCLUDE = 3;  /*!< An include directive (see include_filename, buffer). */
	static const int EOF = 4;      /*!< The end of the current input reached. */
	static const int STOP = 5;     /*!< Early stop (possibly set from a callback). */
} zs_state_t;

/*!
 * \brief Context structure for zone scanner.
 *
 * This structure contains following items:
 *  - Copies of Ragel internal variables. The scanner can be called many times
 *    on smaller parts of zone file/memory. So it is necessary to preserve
 *    internal values between subsequent scanner callings.
 *  - Auxiliary variables which are used during processing zone data.
 *  - Pointers to callback functions and pointer to any arbitrary data which
 *    can be used in callback functions.
 *  - Zone file and error information.
 *  - Output variables (r_ prefix) containing all parts of zone record. These
 *    data are useful during processing via callback function.
 */
typedef struct zs_scanner zs_scanner_t; // Forward declaration due to arguments.
struct zs_scanner {
	/*! Current state (Ragel internals). */
	int      cs;
	/*! Stack top (Ragel internals). */
	int      top;
	/*! Call stack (Ragel internals). */
	int      stack[ZS_RAGEL_STACK_SIZE];

	/*! Indicates whether current record is multiline. */
	bool     multiline;
	/*! Auxiliary number for all numeric operations. */
	uint64_t number64;
	/*! Auxiliary variable for time and other numeric operations. */
	uint64_t number64_tmp;
	/*! Auxiliary variable for float numeric operations. */
	uint32_t decimals;
	/*! Auxiliary variable for float numeric operations. */
	uint32_t decimal_counter;

	/*! Auxiliary variable for item length (label, base64, ...). */
	uint32_t item_length;
	/*! Auxiliary index for item length position in array. */
	uint32_t item_length_position;
	/*! Auxiliary pointer to item length. */
	uint8_t *item_length_location;
	/*! Auxiliary buffer length. Is zero if no comment after a valid record. */
	uint32_t buffer_length;
	/*! Auxiliary buffer. Contains a comment after a valid record. */
	uint8_t  buffer[ZS_MAX_RDATA_LENGTH];
	/*! Auxiliary buffer for current included file name. */
	char     include_filename[ZS_MAX_RDATA_LENGTH];
	/*! Absolute path for relative includes. */
	char     *path;

	/*! Auxiliary array of bitmap window blocks. */
	zs_win_t windows[ZS_BITMAP_WINDOWS];
	/*! Last window block which is used (-1 means no window). */
	int16_t  last_window;
	/*! Auxiliary apl structure. */
	zs_apl_t apl;
	/*! Auxiliary loc structure. */
	zs_loc_t loc;
	/*! Auxiliary IP address storage. */
	uint8_t  addr[ZS_INET6_ADDR_LENGTH];
	/*! Allow text strings longer than 255 characters. */
	bool     long_string;

	/*! Pointer to the actual dname storage (origin/owner/rdata). */
	uint8_t  *dname;
	/*! Pointer to the actual dname length storage. */
	uint32_t *dname_length;
	/*!
	 * Temporary dname length which is copied to dname_length after
	 * dname processing.
	 */
	uint32_t dname_tmp_length;
	/*! Position of the last free r_data byte. */
	uint32_t r_data_tail;

	/*! Length of the current origin. */
	uint32_t zone_origin_length;
	/*!
	 *  Wire format of the current origin (ORIGIN directive sets this).
	 *
	 * \note Maximal dname length check is after each valid label.
	 */
	uint8_t  zone_origin[ZS_MAX_DNAME_LENGTH + ZS_MAX_LABEL_LENGTH];
	/*! Value of the default class. */
	uint16_t default_class;
	/*! Value of the current default ttl (TTL directive sets this). */
	uint32_t default_ttl;

	/*! The current processing state. */
	int state;

	/*! Processing callbacks and auxiliary data. */
	struct {
		/*! Automatic zone processing using record/error callbacks. */
		bool automatic;
		/*! Callback function for correct zone record. */
		void (*record)(zs_scanner_t *);
		/*! Callback function for wrong situations. */
		void (*error)(zs_scanner_t *);
		/*! Arbitrary data useful inside callback functions. */
		void *data;
	} process;

	/*! Input parameters. */
	struct {
		/*! Start of the block. */
		const char *start;
		/*! Current parser position. */
		const char *current;
		/*! End of the block. */
		const char *end;
		/*! Indication for the final block parsing. */
		bool eof;
		/*! Indication of being mmap()-ed (malloc()-ed otherwise). */
		bool mmaped;
	} input;

	/*! File input parameters. */
	struct {
		/*! Zone file name. */
		char *name;
		/*!< File descriptor. */
		int  descriptor;
	} file;

	struct {
		/*! Last occurred error/warning code. */
		int code;
		/*! Error/warning counter. */
		uint64_t counter;
		/*! Indicates serious error - parsing cannot continue. */
		bool fatal;
	} error;

	/*! Zone data line counter. */
	uint64_t line_counter;

	/*! Length of the current record owner. */
	uint32_t r_owner_length;
	/*!
	 * Owner of the current record.
	 *
	 * \note Maximal dname length check is after each valid label.
	 */
	uint8_t  r_owner[ZS_MAX_DNAME_LENGTH + ZS_MAX_LABEL_LENGTH];
	/*! Class of the current record. */
	uint16_t r_class;
	/*! TTL of the current record. */
	uint32_t r_ttl;
	/*! Type of the current record data. */
	uint16_t r_type;
	/*! Length of the current rdata. */
	uint32_t r_data_length;
	/*! Current rdata. */
	uint8_t  r_data[ZS_MAX_RDATA_LENGTH];

	/*
	 * Example: a. IN 60 MX 1 b. ; A comment
	 *
	 *          r_owner_length = 3
	 *          r_owner = 016100
	 *          r_class = 1
	 *          r_ttl = 60
	 *          r_type = 15
	 *          r_data_length = 5
	 *          r_data = 0001016200
	 *          buffer_length = 11
	 *          buffer = " A comment"
	 */
};

/*!
 * \brief Initializes the scanner context.
 *
 * \note Error code is stored in the scanner context.
 *
 * \param scanner  Scanner context.
 * \param origin   Initial zone origin.
 * \param rclass   Zone class value.
 * \param ttl      Initial ttl value.
 *
 * \retval  0  if success.
 * \retval -1  if error.
 */
int zs_init(
	zs_scanner_t *scanner,
	const char *origin,
	const uint16_t rclass,
	const uint32_t ttl
);

/*!
 * \brief Deinitializes the scanner context.
 *
 * \param scanner  Scanner context.
 */
void zs_deinit(
	zs_scanner_t *scanner
);

/*!
 * \brief Sets the scanner to parse a zone data string.
 *
 * \note Error code is stored in the scanner context.
 *
 * \param scanner  Scanner context.
 * \param input    Input zone data string to parse.
 * \param size     Size of the input string.
 *
 * \retval  0  if success.
 * \retval -1  if error.
 */
int zs_set_input_string(
	zs_scanner_t *scanner,
	const char *input,
	size_t size
);

/*!
 * \brief Sets the scanner to parse a zone file..
 *
 * \note Error code is stored in the scanner context.
 *
 * \param scanner    Scanner context.
 * \param file_name  Name of the file to parse.
 *
 * \retval  0  if success.
 * \retval -1  if error.
 */
int zs_set_input_file(
	zs_scanner_t *scanner,
	const char *file_name
);

/*!
 * \brief Sets the scanner processing callbacks for automatic processing.
 *
 * \note Error code is stored in the scanner context.
 *
 * \param scanner         Scanner context.
 * \param process_record  Processing callback function (may be NULL).
 * \param process_error   Error callback function (may be NULL).
 * \param data            Arbitrary data useful in callback functions.
 *
 * \retval  0  if success.
 * \retval -1  if error.
 */
int zs_set_processing(
	zs_scanner_t *scanner,
	void (*process_record)(zs_scanner_t *),
	void (*process_error)(zs_scanner_t *),
	void *data
);

/*!
 * \brief Parses one record from the input.
 *
 * The following processing should be based on the scanner->state.
 *
 * \note Error code and other information are stored in the scanner context.
 *
 * \param scanner  Scanner context.
 *
 * \retval  0  if success.
 * \retval -1  if error.
 */
int zs_parse_record(
	zs_scanner_t *scanner
);

/*!
 * \brief Launches automatic parsing of the whole input.
 *
 * For each correctly recognized record, the record callback is executed.
 * If any syntax error occurs, the error callback is executed.
 *
 * \note Error code and other information are stored in the scanner context.
 *
 * \param scanner  Scanner context.
 *
 * \retval  0  if success.
 * \retval -1  if error.
 */
int zs_parse_all(
	zs_scanner_t *scanner
);
]]

-- Constant table
local zs_state = ffi.new('zs_state_t')

-- Wrap scanner context
local zs_scanner_t = ffi.typeof('zs_scanner_t')
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
