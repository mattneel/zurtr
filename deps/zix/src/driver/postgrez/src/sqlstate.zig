//! Full SQLSTATE enum (PostgreSQL errcodes appendix) + ServerError.
//!
//! Note:
//! - One comptime table is the single source of truth: the enum, fromCode,
//!   and toCode are all generated from it. UNKNOWN is appended for codes the
//!   driver has no mapping for, the raw 5-char code is always kept alongside.
//! - A few condition names repeat across classes in the appendix
//!   (e.g. modifying_sql_data_not_permitted in class 2F and 38). Those carry
//!   the same class prefixes PostgreSQL uses in errcodes.h: SRE_ (sql routine
//!   exception), ERE_ (external routine exception), ERIE_ (external routine
//!   invocation exception), WARNING_ (class 01).

const std = @import("std");
const backend = @import("protocol/backend.zig");

/// code and enum tag name, one row per errcodes appendix entry.
const Entry = struct {
    code: []const u8,
    name: [:0]const u8,
};

const ENTRIES = [_]Entry{
    // Class 00: Successful Completion
    .{ .code = "00000", .name = "SUCCESSFUL_COMPLETION" },
    // Class 01: Warning
    .{ .code = "01000", .name = "WARNING" },
    .{ .code = "0100C", .name = "DYNAMIC_RESULT_SETS_RETURNED" },
    .{ .code = "01008", .name = "IMPLICIT_ZERO_BIT_PADDING" },
    .{ .code = "01003", .name = "NULL_VALUE_ELIMINATED_IN_SET_FUNCTION" },
    .{ .code = "01007", .name = "PRIVILEGE_NOT_GRANTED" },
    .{ .code = "01006", .name = "PRIVILEGE_NOT_REVOKED" },
    .{ .code = "01004", .name = "WARNING_STRING_DATA_RIGHT_TRUNCATION" },
    .{ .code = "01P01", .name = "DEPRECATED_FEATURE" },
    // Class 02: No Data
    .{ .code = "02000", .name = "NO_DATA" },
    .{ .code = "02001", .name = "NO_ADDITIONAL_DYNAMIC_RESULT_SETS_RETURNED" },
    // Class 03: SQL Statement Not Yet Complete
    .{ .code = "03000", .name = "SQL_STATEMENT_NOT_YET_COMPLETE" },
    // Class 08: Connection Exception
    .{ .code = "08000", .name = "CONNECTION_EXCEPTION" },
    .{ .code = "08003", .name = "CONNECTION_DOES_NOT_EXIST" },
    .{ .code = "08006", .name = "CONNECTION_FAILURE" },
    .{ .code = "08001", .name = "SQLCLIENT_UNABLE_TO_ESTABLISH_SQLCONNECTION" },
    .{ .code = "08004", .name = "SQLSERVER_REJECTED_ESTABLISHMENT_OF_SQLCONNECTION" },
    .{ .code = "08007", .name = "TRANSACTION_RESOLUTION_UNKNOWN" },
    .{ .code = "08P01", .name = "PROTOCOL_VIOLATION" },
    // Class 09: Triggered Action Exception
    .{ .code = "09000", .name = "TRIGGERED_ACTION_EXCEPTION" },
    // Class 0A: Feature Not Supported
    .{ .code = "0A000", .name = "FEATURE_NOT_SUPPORTED" },
    // Class 0B: Invalid Transaction Initiation
    .{ .code = "0B000", .name = "INVALID_TRANSACTION_INITIATION" },
    // Class 0F: Locator Exception
    .{ .code = "0F000", .name = "LOCATOR_EXCEPTION" },
    .{ .code = "0F001", .name = "INVALID_LOCATOR_SPECIFICATION" },
    // Class 0L: Invalid Grantor
    .{ .code = "0L000", .name = "INVALID_GRANTOR" },
    .{ .code = "0LP01", .name = "INVALID_GRANT_OPERATION" },
    // Class 0P: Invalid Role Specification
    .{ .code = "0P000", .name = "INVALID_ROLE_SPECIFICATION" },
    // Class 0Z: Diagnostics Exception
    .{ .code = "0Z000", .name = "DIAGNOSTICS_EXCEPTION" },
    .{ .code = "0Z002", .name = "STACKED_DIAGNOSTICS_ACCESSED_WITHOUT_ACTIVE_HANDLER" },
    // Class 20: Case Not Found
    .{ .code = "20000", .name = "CASE_NOT_FOUND" },
    // Class 21: Cardinality Violation
    .{ .code = "21000", .name = "CARDINALITY_VIOLATION" },
    // Class 22: Data Exception
    .{ .code = "22000", .name = "DATA_EXCEPTION" },
    .{ .code = "2202E", .name = "ARRAY_SUBSCRIPT_ERROR" },
    .{ .code = "22021", .name = "CHARACTER_NOT_IN_REPERTOIRE" },
    .{ .code = "22008", .name = "DATETIME_FIELD_OVERFLOW" },
    .{ .code = "22012", .name = "DIVISION_BY_ZERO" },
    .{ .code = "22005", .name = "ERROR_IN_ASSIGNMENT" },
    .{ .code = "2200B", .name = "ESCAPE_CHARACTER_CONFLICT" },
    .{ .code = "22022", .name = "INDICATOR_OVERFLOW" },
    .{ .code = "22015", .name = "INTERVAL_FIELD_OVERFLOW" },
    .{ .code = "2201E", .name = "INVALID_ARGUMENT_FOR_LOGARITHM" },
    .{ .code = "22014", .name = "INVALID_ARGUMENT_FOR_NTILE_FUNCTION" },
    .{ .code = "22016", .name = "INVALID_ARGUMENT_FOR_NTH_VALUE_FUNCTION" },
    .{ .code = "2201F", .name = "INVALID_ARGUMENT_FOR_POWER_FUNCTION" },
    .{ .code = "2201G", .name = "INVALID_ARGUMENT_FOR_WIDTH_BUCKET_FUNCTION" },
    .{ .code = "22018", .name = "INVALID_CHARACTER_VALUE_FOR_CAST" },
    .{ .code = "22007", .name = "INVALID_DATETIME_FORMAT" },
    .{ .code = "22019", .name = "INVALID_ESCAPE_CHARACTER" },
    .{ .code = "2200D", .name = "INVALID_ESCAPE_OCTET" },
    .{ .code = "22025", .name = "INVALID_ESCAPE_SEQUENCE" },
    .{ .code = "22P06", .name = "NONSTANDARD_USE_OF_ESCAPE_CHARACTER" },
    .{ .code = "22010", .name = "INVALID_INDICATOR_PARAMETER_VALUE" },
    .{ .code = "22023", .name = "INVALID_PARAMETER_VALUE" },
    .{ .code = "22013", .name = "INVALID_PRECEDING_OR_FOLLOWING_SIZE" },
    .{ .code = "2201B", .name = "INVALID_REGULAR_EXPRESSION" },
    .{ .code = "2201W", .name = "INVALID_ROW_COUNT_IN_LIMIT_CLAUSE" },
    .{ .code = "2201X", .name = "INVALID_ROW_COUNT_IN_RESULT_OFFSET_CLAUSE" },
    .{ .code = "2202H", .name = "INVALID_TABLESAMPLE_ARGUMENT" },
    .{ .code = "2202G", .name = "INVALID_TABLESAMPLE_REPEAT" },
    .{ .code = "22009", .name = "INVALID_TIME_ZONE_DISPLACEMENT_VALUE" },
    .{ .code = "2200C", .name = "INVALID_USE_OF_ESCAPE_CHARACTER" },
    .{ .code = "2200G", .name = "MOST_SPECIFIC_TYPE_MISMATCH" },
    .{ .code = "22004", .name = "NULL_VALUE_NOT_ALLOWED" },
    .{ .code = "22002", .name = "NULL_VALUE_NO_INDICATOR_PARAMETER" },
    .{ .code = "22003", .name = "NUMERIC_VALUE_OUT_OF_RANGE" },
    .{ .code = "2200H", .name = "SEQUENCE_GENERATOR_LIMIT_EXCEEDED" },
    .{ .code = "22026", .name = "STRING_DATA_LENGTH_MISMATCH" },
    .{ .code = "22001", .name = "STRING_DATA_RIGHT_TRUNCATION" },
    .{ .code = "22011", .name = "SUBSTRING_ERROR" },
    .{ .code = "22027", .name = "TRIM_ERROR" },
    .{ .code = "22024", .name = "UNTERMINATED_C_STRING" },
    .{ .code = "2200F", .name = "ZERO_LENGTH_CHARACTER_STRING" },
    .{ .code = "22P01", .name = "FLOATING_POINT_EXCEPTION" },
    .{ .code = "22P02", .name = "INVALID_TEXT_REPRESENTATION" },
    .{ .code = "22P03", .name = "INVALID_BINARY_REPRESENTATION" },
    .{ .code = "22P04", .name = "BAD_COPY_FILE_FORMAT" },
    .{ .code = "22P05", .name = "UNTRANSLATABLE_CHARACTER" },
    .{ .code = "2200L", .name = "NOT_AN_XML_DOCUMENT" },
    .{ .code = "2200M", .name = "INVALID_XML_DOCUMENT" },
    .{ .code = "2200N", .name = "INVALID_XML_CONTENT" },
    .{ .code = "2200S", .name = "INVALID_XML_COMMENT" },
    .{ .code = "2200T", .name = "INVALID_XML_PROCESSING_INSTRUCTION" },
    .{ .code = "22030", .name = "DUPLICATE_JSON_OBJECT_KEY_VALUE" },
    .{ .code = "22031", .name = "INVALID_ARGUMENT_FOR_SQL_JSON_DATETIME_FUNCTION" },
    .{ .code = "22032", .name = "INVALID_JSON_TEXT" },
    .{ .code = "22033", .name = "INVALID_SQL_JSON_SUBSCRIPT" },
    .{ .code = "22034", .name = "MORE_THAN_ONE_SQL_JSON_ITEM" },
    .{ .code = "22035", .name = "NO_SQL_JSON_ITEM" },
    .{ .code = "22036", .name = "NON_NUMERIC_SQL_JSON_ITEM" },
    .{ .code = "22037", .name = "NON_UNIQUE_KEYS_IN_A_JSON_OBJECT" },
    .{ .code = "22038", .name = "SINGLETON_SQL_JSON_ITEM_REQUIRED" },
    .{ .code = "22039", .name = "SQL_JSON_ARRAY_NOT_FOUND" },
    .{ .code = "2203A", .name = "SQL_JSON_MEMBER_NOT_FOUND" },
    .{ .code = "2203B", .name = "SQL_JSON_NUMBER_NOT_FOUND" },
    .{ .code = "2203C", .name = "SQL_JSON_OBJECT_NOT_FOUND" },
    .{ .code = "2203D", .name = "TOO_MANY_JSON_ARRAY_ELEMENTS" },
    .{ .code = "2203E", .name = "TOO_MANY_JSON_OBJECT_MEMBERS" },
    .{ .code = "2203F", .name = "SQL_JSON_SCALAR_REQUIRED" },
    .{ .code = "2203G", .name = "SQL_JSON_ITEM_CANNOT_BE_CAST_TO_TARGET_TYPE" },
    // Class 23: Integrity Constraint Violation
    .{ .code = "23000", .name = "INTEGRITY_CONSTRAINT_VIOLATION" },
    .{ .code = "23001", .name = "RESTRICT_VIOLATION" },
    .{ .code = "23502", .name = "NOT_NULL_VIOLATION" },
    .{ .code = "23503", .name = "FOREIGN_KEY_VIOLATION" },
    .{ .code = "23505", .name = "UNIQUE_VIOLATION" },
    .{ .code = "23514", .name = "CHECK_VIOLATION" },
    .{ .code = "23P01", .name = "EXCLUSION_VIOLATION" },
    // Class 24: Invalid Cursor State
    .{ .code = "24000", .name = "INVALID_CURSOR_STATE" },
    // Class 25: Invalid Transaction State
    .{ .code = "25000", .name = "INVALID_TRANSACTION_STATE" },
    .{ .code = "25001", .name = "ACTIVE_SQL_TRANSACTION" },
    .{ .code = "25002", .name = "BRANCH_TRANSACTION_ALREADY_ACTIVE" },
    .{ .code = "25008", .name = "HELD_CURSOR_REQUIRES_SAME_ISOLATION_LEVEL" },
    .{ .code = "25003", .name = "INAPPROPRIATE_ACCESS_MODE_FOR_BRANCH_TRANSACTION" },
    .{ .code = "25004", .name = "INAPPROPRIATE_ISOLATION_LEVEL_FOR_BRANCH_TRANSACTION" },
    .{ .code = "25005", .name = "NO_ACTIVE_SQL_TRANSACTION_FOR_BRANCH_TRANSACTION" },
    .{ .code = "25006", .name = "READ_ONLY_SQL_TRANSACTION" },
    .{ .code = "25007", .name = "SCHEMA_AND_DATA_STATEMENT_MIXING_NOT_SUPPORTED" },
    .{ .code = "25P01", .name = "NO_ACTIVE_SQL_TRANSACTION" },
    .{ .code = "25P02", .name = "IN_FAILED_SQL_TRANSACTION" },
    .{ .code = "25P03", .name = "IDLE_IN_TRANSACTION_SESSION_TIMEOUT" },
    .{ .code = "25P04", .name = "TRANSACTION_TIMEOUT" },
    // Class 26: Invalid SQL Statement Name
    .{ .code = "26000", .name = "INVALID_SQL_STATEMENT_NAME" },
    // Class 27: Triggered Data Change Violation
    .{ .code = "27000", .name = "TRIGGERED_DATA_CHANGE_VIOLATION" },
    // Class 28: Invalid Authorization Specification
    .{ .code = "28000", .name = "INVALID_AUTHORIZATION_SPECIFICATION" },
    .{ .code = "28P01", .name = "INVALID_PASSWORD" },
    // Class 2B: Dependent Privilege Descriptors Still Exist
    .{ .code = "2B000", .name = "DEPENDENT_PRIVILEGE_DESCRIPTORS_STILL_EXIST" },
    .{ .code = "2BP01", .name = "DEPENDENT_OBJECTS_STILL_EXIST" },
    // Class 2D: Invalid Transaction Termination
    .{ .code = "2D000", .name = "INVALID_TRANSACTION_TERMINATION" },
    // Class 2F: SQL Routine Exception
    .{ .code = "2F000", .name = "SQL_ROUTINE_EXCEPTION" },
    .{ .code = "2F005", .name = "SRE_FUNCTION_EXECUTED_NO_RETURN_STATEMENT" },
    .{ .code = "2F002", .name = "SRE_MODIFYING_SQL_DATA_NOT_PERMITTED" },
    .{ .code = "2F003", .name = "SRE_PROHIBITED_SQL_STATEMENT_ATTEMPTED" },
    .{ .code = "2F004", .name = "SRE_READING_SQL_DATA_NOT_PERMITTED" },
    // Class 34: Invalid Cursor Name
    .{ .code = "34000", .name = "INVALID_CURSOR_NAME" },
    // Class 38: External Routine Exception
    .{ .code = "38000", .name = "EXTERNAL_ROUTINE_EXCEPTION" },
    .{ .code = "38001", .name = "ERE_CONTAINING_SQL_NOT_PERMITTED" },
    .{ .code = "38002", .name = "ERE_MODIFYING_SQL_DATA_NOT_PERMITTED" },
    .{ .code = "38003", .name = "ERE_PROHIBITED_SQL_STATEMENT_ATTEMPTED" },
    .{ .code = "38004", .name = "ERE_READING_SQL_DATA_NOT_PERMITTED" },
    // Class 39: External Routine Invocation Exception
    .{ .code = "39000", .name = "EXTERNAL_ROUTINE_INVOCATION_EXCEPTION" },
    .{ .code = "39001", .name = "ERIE_INVALID_SQLSTATE_RETURNED" },
    .{ .code = "39004", .name = "ERIE_NULL_VALUE_NOT_ALLOWED" },
    .{ .code = "39P01", .name = "ERIE_TRIGGER_PROTOCOL_VIOLATED" },
    .{ .code = "39P02", .name = "ERIE_SRF_PROTOCOL_VIOLATED" },
    .{ .code = "39P03", .name = "ERIE_EVENT_TRIGGER_PROTOCOL_VIOLATED" },
    // Class 3B: Savepoint Exception
    .{ .code = "3B000", .name = "SAVEPOINT_EXCEPTION" },
    .{ .code = "3B001", .name = "INVALID_SAVEPOINT_SPECIFICATION" },
    // Class 3D: Invalid Catalog Name
    .{ .code = "3D000", .name = "INVALID_CATALOG_NAME" },
    // Class 3F: Invalid Schema Name
    .{ .code = "3F000", .name = "INVALID_SCHEMA_NAME" },
    // Class 40: Transaction Rollback
    .{ .code = "40000", .name = "TRANSACTION_ROLLBACK" },
    .{ .code = "40002", .name = "TRANSACTION_INTEGRITY_CONSTRAINT_VIOLATION" },
    .{ .code = "40001", .name = "SERIALIZATION_FAILURE" },
    .{ .code = "40003", .name = "STATEMENT_COMPLETION_UNKNOWN" },
    .{ .code = "40P01", .name = "DEADLOCK_DETECTED" },
    // Class 42: Syntax Error or Access Rule Violation
    .{ .code = "42000", .name = "SYNTAX_ERROR_OR_ACCESS_RULE_VIOLATION" },
    .{ .code = "42601", .name = "SYNTAX_ERROR" },
    .{ .code = "42501", .name = "INSUFFICIENT_PRIVILEGE" },
    .{ .code = "42846", .name = "CANNOT_COERCE" },
    .{ .code = "42803", .name = "GROUPING_ERROR" },
    .{ .code = "42P20", .name = "WINDOWING_ERROR" },
    .{ .code = "42P19", .name = "INVALID_RECURSION" },
    .{ .code = "42830", .name = "INVALID_FOREIGN_KEY" },
    .{ .code = "42602", .name = "INVALID_NAME" },
    .{ .code = "42622", .name = "NAME_TOO_LONG" },
    .{ .code = "42939", .name = "RESERVED_NAME" },
    .{ .code = "42804", .name = "DATATYPE_MISMATCH" },
    .{ .code = "42P18", .name = "INDETERMINATE_DATATYPE" },
    .{ .code = "42P21", .name = "COLLATION_MISMATCH" },
    .{ .code = "42P22", .name = "INDETERMINATE_COLLATION" },
    .{ .code = "42809", .name = "WRONG_OBJECT_TYPE" },
    .{ .code = "428C9", .name = "GENERATED_ALWAYS" },
    .{ .code = "42703", .name = "UNDEFINED_COLUMN" },
    .{ .code = "42883", .name = "UNDEFINED_FUNCTION" },
    .{ .code = "42P01", .name = "UNDEFINED_TABLE" },
    .{ .code = "42P02", .name = "UNDEFINED_PARAMETER" },
    .{ .code = "42704", .name = "UNDEFINED_OBJECT" },
    .{ .code = "42701", .name = "DUPLICATE_COLUMN" },
    .{ .code = "42P03", .name = "DUPLICATE_CURSOR" },
    .{ .code = "42P04", .name = "DUPLICATE_DATABASE" },
    .{ .code = "42723", .name = "DUPLICATE_FUNCTION" },
    .{ .code = "42P05", .name = "DUPLICATE_PREPARED_STATEMENT" },
    .{ .code = "42P06", .name = "DUPLICATE_SCHEMA" },
    .{ .code = "42P07", .name = "DUPLICATE_TABLE" },
    .{ .code = "42712", .name = "DUPLICATE_ALIAS" },
    .{ .code = "42710", .name = "DUPLICATE_OBJECT" },
    .{ .code = "42702", .name = "AMBIGUOUS_COLUMN" },
    .{ .code = "42725", .name = "AMBIGUOUS_FUNCTION" },
    .{ .code = "42P08", .name = "AMBIGUOUS_PARAMETER" },
    .{ .code = "42P09", .name = "AMBIGUOUS_ALIAS" },
    .{ .code = "42P10", .name = "INVALID_COLUMN_REFERENCE" },
    .{ .code = "42611", .name = "INVALID_COLUMN_DEFINITION" },
    .{ .code = "42P11", .name = "INVALID_CURSOR_DEFINITION" },
    .{ .code = "42P12", .name = "INVALID_DATABASE_DEFINITION" },
    .{ .code = "42P13", .name = "INVALID_FUNCTION_DEFINITION" },
    .{ .code = "42P14", .name = "INVALID_PREPARED_STATEMENT_DEFINITION" },
    .{ .code = "42P15", .name = "INVALID_SCHEMA_DEFINITION" },
    .{ .code = "42P16", .name = "INVALID_TABLE_DEFINITION" },
    .{ .code = "42P17", .name = "INVALID_OBJECT_DEFINITION" },
    // Class 44: WITH CHECK OPTION Violation
    .{ .code = "44000", .name = "WITH_CHECK_OPTION_VIOLATION" },
    // Class 53: Insufficient Resources
    .{ .code = "53000", .name = "INSUFFICIENT_RESOURCES" },
    .{ .code = "53100", .name = "DISK_FULL" },
    .{ .code = "53200", .name = "OUT_OF_MEMORY" },
    .{ .code = "53300", .name = "TOO_MANY_CONNECTIONS" },
    .{ .code = "53400", .name = "CONFIGURATION_LIMIT_EXCEEDED" },
    // Class 54: Program Limit Exceeded
    .{ .code = "54000", .name = "PROGRAM_LIMIT_EXCEEDED" },
    .{ .code = "54001", .name = "STATEMENT_TOO_COMPLEX" },
    .{ .code = "54011", .name = "TOO_MANY_COLUMNS" },
    .{ .code = "54023", .name = "TOO_MANY_ARGUMENTS" },
    // Class 55: Object Not In Prerequisite State
    .{ .code = "55000", .name = "OBJECT_NOT_IN_PREREQUISITE_STATE" },
    .{ .code = "55006", .name = "OBJECT_IN_USE" },
    .{ .code = "55P02", .name = "CANT_CHANGE_RUNTIME_PARAM" },
    .{ .code = "55P03", .name = "LOCK_NOT_AVAILABLE" },
    .{ .code = "55P04", .name = "UNSAFE_NEW_ENUM_VALUE_USAGE" },
    // Class 57: Operator Intervention
    .{ .code = "57000", .name = "OPERATOR_INTERVENTION" },
    .{ .code = "57014", .name = "QUERY_CANCELED" },
    .{ .code = "57P01", .name = "ADMIN_SHUTDOWN" },
    .{ .code = "57P02", .name = "CRASH_SHUTDOWN" },
    .{ .code = "57P03", .name = "CANNOT_CONNECT_NOW" },
    .{ .code = "57P04", .name = "DATABASE_DROPPED" },
    .{ .code = "57P05", .name = "IDLE_SESSION_TIMEOUT" },
    // Class 58: System Error (external to PostgreSQL)
    .{ .code = "58000", .name = "SYSTEM_ERROR" },
    .{ .code = "58030", .name = "IO_ERROR" },
    .{ .code = "58P01", .name = "UNDEFINED_FILE" },
    .{ .code = "58P02", .name = "DUPLICATE_FILE" },
    // Class 72: Snapshot Failure
    .{ .code = "72000", .name = "SNAPSHOT_TOO_OLD" },
    // Class F0: Configuration File Error
    .{ .code = "F0000", .name = "CONFIG_FILE_ERROR" },
    .{ .code = "F0001", .name = "LOCK_FILE_EXISTS" },
    // Class HV: Foreign Data Wrapper Error (SQL/MED)
    .{ .code = "HV000", .name = "FDW_ERROR" },
    .{ .code = "HV005", .name = "FDW_COLUMN_NAME_NOT_FOUND" },
    .{ .code = "HV002", .name = "FDW_DYNAMIC_PARAMETER_VALUE_NEEDED" },
    .{ .code = "HV010", .name = "FDW_FUNCTION_SEQUENCE_ERROR" },
    .{ .code = "HV021", .name = "FDW_INCONSISTENT_DESCRIPTOR_INFORMATION" },
    .{ .code = "HV024", .name = "FDW_INVALID_ATTRIBUTE_VALUE" },
    .{ .code = "HV007", .name = "FDW_INVALID_COLUMN_NAME" },
    .{ .code = "HV008", .name = "FDW_INVALID_COLUMN_NUMBER" },
    .{ .code = "HV004", .name = "FDW_INVALID_DATA_TYPE" },
    .{ .code = "HV006", .name = "FDW_INVALID_DATA_TYPE_DESCRIPTORS" },
    .{ .code = "HV091", .name = "FDW_INVALID_DESCRIPTOR_FIELD_IDENTIFIER" },
    .{ .code = "HV00B", .name = "FDW_INVALID_HANDLE" },
    .{ .code = "HV00C", .name = "FDW_INVALID_OPTION_INDEX" },
    .{ .code = "HV00D", .name = "FDW_INVALID_OPTION_NAME" },
    .{ .code = "HV090", .name = "FDW_INVALID_STRING_LENGTH_OR_BUFFER_LENGTH" },
    .{ .code = "HV00A", .name = "FDW_INVALID_STRING_FORMAT" },
    .{ .code = "HV009", .name = "FDW_INVALID_USE_OF_NULL_POINTER" },
    .{ .code = "HV014", .name = "FDW_TOO_MANY_HANDLES" },
    .{ .code = "HV001", .name = "FDW_OUT_OF_MEMORY" },
    .{ .code = "HV00P", .name = "FDW_NO_SCHEMAS" },
    .{ .code = "HV00J", .name = "FDW_OPTION_NAME_NOT_FOUND" },
    .{ .code = "HV00K", .name = "FDW_REPLY_HANDLE" },
    .{ .code = "HV00Q", .name = "FDW_SCHEMA_NOT_FOUND" },
    .{ .code = "HV00R", .name = "FDW_TABLE_NOT_FOUND" },
    .{ .code = "HV00L", .name = "FDW_UNABLE_TO_CREATE_EXECUTION" },
    .{ .code = "HV00M", .name = "FDW_UNABLE_TO_CREATE_REPLY" },
    .{ .code = "HV00N", .name = "FDW_UNABLE_TO_ESTABLISH_CONNECTION" },
    // Class P0: PL/pgSQL Error
    .{ .code = "P0000", .name = "PLPGSQL_ERROR" },
    .{ .code = "P0001", .name = "RAISE_EXCEPTION" },
    .{ .code = "P0002", .name = "NO_DATA_FOUND" },
    .{ .code = "P0003", .name = "TOO_MANY_ROWS" },
    .{ .code = "P0004", .name = "ASSERT_FAILURE" },
    // Class XX: Internal Error
    .{ .code = "XX000", .name = "INTERNAL_ERROR" },
    .{ .code = "XX001", .name = "DATA_CORRUPTED" },
    .{ .code = "XX002", .name = "INDEX_CORRUPTED" },
};

// --------------------------------------------------------- //

/// Every SQLSTATE the errcodes appendix defines, plus UNKNOWN for anything
/// the table does not cover. Generated from `ENTRIES`, tag order = table
/// order, UNKNOWN last.
pub const SqlState = @Enum(u16, .exhaustive, names: {
    var names: [ENTRIES.len + 1][]const u8 = undefined;
    for (ENTRIES, 0..) |entry, index| names[index] = entry.name;
    names[ENTRIES.len] = "UNKNOWN";

    break :names &names;
}, values: {
    var values: [ENTRIES.len + 1]u16 = undefined;
    for (&values, 0..) |*value, index| value.* = index;

    break :values &values;
});

const CODE_MAP = blk: {
    var pairs: [ENTRIES.len]struct { []const u8, SqlState } = undefined;

    for (ENTRIES, 0..) |entry, index| {
        pairs[index] = .{ entry.code, @enumFromInt(index) };
    }

    break :blk std.StaticStringMap(SqlState).initComptime(pairs);
};

/// Map a raw 5-char SQLSTATE to its enum value, UNKNOWN when unmapped.
pub fn fromCode(code: []const u8) SqlState {
    return CODE_MAP.get(code) orelse .UNKNOWN;
}

/// The raw 5-char code of a mapped enum value, "?????" for UNKNOWN.
pub fn toCode(state: SqlState) []const u8 {
    if (state == .UNKNOWN) return "?????";

    return ENTRIES[@intFromEnum(state)].code;
}

// --------------------------------------------------------- //

/// The last error the server reported on a connection. Owns copies of the
/// interesting fields so it outlives the receive buffer.
///
/// Note:
/// - message and detail are truncated to their buffer sizes, long server
///   messages keep the head.
pub const ServerError = struct {
    state: SqlState = .UNKNOWN,
    /// Raw 5-char SQLSTATE, always kept alongside the mapped enum.
    code: [5]u8 = @splat('0'),

    severity_buf: [16]u8 = undefined,
    severity_len: usize = 0,
    message_buf: [512]u8 = undefined,
    message_len: usize = 0,
    detail_buf: [256]u8 = undefined,
    detail_len: usize = 0,

    /// Capture an ErrorResponse into owned buffers.
    pub fn capture(self: *ServerError, fields: backend.Fields) void {
        const raw_code = fields.sqlstateCode();
        self.state = fromCode(raw_code);
        self.code = @splat('0');
        const code_len = @min(raw_code.len, self.code.len);
        @memcpy(self.code[0..code_len], raw_code[0..code_len]);

        self.severity_len = copyTruncated(&self.severity_buf, fields.severity());
        self.message_len = copyTruncated(&self.message_buf, fields.message());
        self.detail_len = copyTruncated(&self.detail_buf, fields.get('D') orelse "");
    }

    pub fn severity(self: *const ServerError) []const u8 {
        return self.severity_buf[0..self.severity_len];
    }

    pub fn message(self: *const ServerError) []const u8 {
        return self.message_buf[0..self.message_len];
    }

    pub fn detail(self: *const ServerError) []const u8 {
        return self.detail_buf[0..self.detail_len];
    }
};

fn copyTruncated(dst: []u8, src: []const u8) usize {
    const len = @min(dst.len, src.len);
    @memcpy(dst[0..len], src[0..len]);

    return len;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez: fromCode maps known codes" {
    try testing.expectEqual(SqlState.SUCCESSFUL_COMPLETION, fromCode("00000"));
    try testing.expectEqual(SqlState.UNIQUE_VIOLATION, fromCode("23505"));
    try testing.expectEqual(SqlState.SERIALIZATION_FAILURE, fromCode("40001"));
    try testing.expectEqual(SqlState.DEADLOCK_DETECTED, fromCode("40P01"));
    try testing.expectEqual(SqlState.INVALID_PASSWORD, fromCode("28P01"));
    try testing.expectEqual(SqlState.TRANSACTION_TIMEOUT, fromCode("25P04"));
    try testing.expectEqual(SqlState.INDEX_CORRUPTED, fromCode("XX002"));
}

test "postgrez: fromCode maps unmapped input to UNKNOWN" {
    try testing.expectEqual(SqlState.UNKNOWN, fromCode("ZZZZZ"));
    try testing.expectEqual(SqlState.UNKNOWN, fromCode(""));
    try testing.expectEqual(SqlState.UNKNOWN, fromCode("2350"));
}

test "postgrez: toCode round-trips every entry" {
    for (ENTRIES) |entry| {
        const state = fromCode(entry.code);
        try testing.expect(state != .UNKNOWN);
        try testing.expectEqualStrings(entry.code, toCode(state));
    }

    try testing.expectEqualStrings("?????", toCode(.UNKNOWN));
}

test "postgrez: entry codes are unique and 5 chars" {
    for (ENTRIES, 0..) |entry, index| {
        try testing.expectEqual(@as(usize, 5), entry.code.len);

        for (ENTRIES[index + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, entry.code, other.code));
        }
    }
}

test "postgrez: ServerError captures an ErrorResponse" {
    const payload = "SERROR\x00C23505\x00Mduplicate key value\x00Dalready exists\x00\x00";
    const decoded = try backend.decode('E', payload);

    var server_error = ServerError{};
    server_error.capture(decoded.error_response);

    try testing.expectEqual(SqlState.UNIQUE_VIOLATION, server_error.state);
    try testing.expectEqualStrings("23505", &server_error.code);
    try testing.expectEqualStrings("ERROR", server_error.severity());
    try testing.expectEqualStrings("duplicate key value", server_error.message());
    try testing.expectEqualStrings("already exists", server_error.detail());
}

test "postgrez: ServerError keeps the raw code for unmapped states" {
    const payload = "SFATAL\x00CZZ123\x00Mstrange\x00\x00";
    const decoded = try backend.decode('E', payload);

    var server_error = ServerError{};
    server_error.capture(decoded.error_response);

    try testing.expectEqual(SqlState.UNKNOWN, server_error.state);
    try testing.expectEqualStrings("ZZ123", &server_error.code);
}
