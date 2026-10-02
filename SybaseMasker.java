import org.apache.poi.ss.usermodel.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.sql.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Java 17 / SAP Sybase ASE 16 adaptation of the photographed OracleMasker.
 *
 * SETUP
 * Keep your project's Apache POI poi-ooxml and SLF4J dependencies. Add your
 * organisation's SAP jConnect jconn4.jar to the runtime classpath (not Oracle JDBC).
 * No compile-time jConnect classes are used.
 *
 * Environment variables:
 *   ASE_JDBC_URL     jdbc:sybase:Tds:HOST:PORT/DATABASE
 *   ASE_JDBC_USER    database login
 *   ASE_JDBC_PASSWORD
 *   MASKING_KEY_BASE64  Base64 of at least 32 cryptographically random bytes.
 * Optional:
 *   MASK_EXCEL_PATH  defaults to src/main/resources/fullAnnon.xlsx
 *   ASE_OWNER        defaults to dbo (NOT the login name)
 *   MASK_BATCH_SIZE  defaults to 1000; range 1..5000
 *
 * First Excel sheet: column A = owner.table (or table), column B = column.
 * One column per row; repeated table names are grouped. Optional first-row
 * headings: Table / Column, or TABLE_NAME / COLUMN_NAME. Preserve identifier case.
 * Database is selected by JDBC URL; database.owner.table names are not accepted.
 *
 * Run with no arguments to validate metadata only; run with --execute to update.
 * Example classpath for an existing compiled class plus dependency jars:
 *   java -cp "target/classes;lib/*" SybaseMasker
 *   java -cp "target/classes;lib/*" SybaseMasker --execute
 * On Linux replace the classpath semicolon with a colon. In an IDE, set the
 * environment variables and use --execute as the program argument after validation.
 *
 * BEHAVIOUR / LIMITS
 * - Requires a declared primary key. No Oracle ROWID emulation or schema changes.
 * - PK and declared FK columns cannot be masked by this generic implementation.
 * - Uses bounded keyset pages, closing each SELECT before executing UPDATE batches.
 * - Acquires an exclusive table lock per table; checks the ASE lock error code.
 * - Commits per table, as in the original. Failure rolls back the CURRENT table;
 *   earlier tables remain committed. Do not blindly rerun a partially completed run.
 * - Validate first, then execute against an isolated, backed-up database copy with
 *   writers stopped. Table locks last until commit; size the transaction log for
 *   the whole table. Batch size is NOT a commit interval.
 * - Triggers, check constraints, unique constraints, application-level references
 *   and cross-database relationships need application-specific review. Constraints
 *   stay enabled; collisions/constraint failures roll back the current table.
 * - Keyed deterministic masking is pseudonymisation, not a guarantee of irreversible
 *   anonymisation. Equality/length patterns remain; collisions are possible. Equal
 *   text values get equal masks with the same key. Numeric masks additionally depend
 *   on the target domain. Outputs differ from OracleMasker's Random(hashCode()).
 * - Text uses ASCII alphanumeric replacements of the same Java UTF-16 length;
 *   fixed-width padding returned by JDBC is included. Byte length may differ.
 * - Numeric values respect storage bounds. Decimal scale is retained; signs,
 *   original digit count, business distributions and formatting are not retained.
 * - text/unitext, dates, binary/image, bit and other unsupported types are rejected,
 *   never silently left unchanged. LOBs need a separately tested streaming path.
 * - Validation checks metadata, not data or UPDATE/trigger execution. No live ASE
 *   integration test was available when this class was produced.
 */
public final class SybaseMasker {
    private static final Logger LOG = LoggerFactory.getLogger(SybaseMasker.class);
    private static final String ALPHANUM =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final Set<String> TEXT_TYPES = Set.of(
            "char", "varchar", "nchar", "nvarchar", "unichar", "univarchar");
    private static final Set<String> NUMERIC_TYPES = Set.of(
            "tinyint", "smallint", "int", "bigint", "unsigned smallint",
            "unsigned int", "unsigned bigint", "decimal", "numeric",
            "money", "smallmoney", "real", "float", "double precision");

    private SybaseMasker() { }

    public static void main(String[] args) throws Exception {
        if (args.length > 1 || (args.length == 1 && !"--execute".equals(args[0]))) {
            throw new IllegalArgumentException("Usage: SybaseMasker [--execute]");
        }
        boolean execute = args.length == 1;
        String excel = env("MASK_EXCEL_PATH", "src/main/resources/fullAnnon.xlsx");
        String owner = env("ASE_OWNER", "dbo");
        int batchSize = Integer.parseInt(env("MASK_BATCH_SIZE", "1000"));
        if (batchSize < 1 || batchSize > 5000) {
            throw new IllegalArgumentException("MASK_BATCH_SIZE must be 1..5000");
        }
        Map<TableId, Set<String>> mapping = readExcelMapping(excel, owner);
        byte[] key = execute ? Base64.getDecoder().decode(required("MASKING_KEY_BASE64")) : null;
        if (execute && key.length < 32) {
            throw new IllegalArgumentException("Masking key must contain at least 32 random bytes");
        }
        Class.forName("com.sybase.jdbc4.jdbc.SybDriver");
        String url = required("ASE_JDBC_URL");
        if (!url.startsWith("jdbc:sybase:Tds:")) {
            throw new IllegalArgumentException("Expected a SAP jConnect jdbc:sybase:Tds: URL");
        }
        Properties props = new Properties();
        props.setProperty("user", required("ASE_JDBC_USER"));
        props.setProperty("password", required("ASE_JDBC_PASSWORD"));
        props.setProperty("EXECUTE_BATCH_PAST_ERRORS", "false");
        try (Connection conn = DriverManager.getConnection(url, props)) {
            conn.setAutoCommit(false);
            try {
                try (Statement st = conn.createStatement()) {
                    st.execute("set quoted_identifier on");
                    st.execute("set nocount off");
                    st.execute("set rowcount 0");
                    st.execute("set string_rtruncation on");
                }
                String catalog;
                try (Statement st = conn.createStatement();
                     ResultSet rs = st.executeQuery("select db_name()")) {
                    rs.next();
                    catalog = rs.getString(1);
                }
                Map<Integer, String> baseTypes = fetchBaseTypes(conn);
                List<TablePlan> plans = new ArrayList<>();
                // Validate EVERY table before modifying the first one.
                for (Map.Entry<TableId, Set<String>> entry : mapping.entrySet()) {
                    plans.add(validateTable(conn, catalog, entry.getKey(), entry.getValue(), baseTypes));
                }
                conn.commit();
                LOG.info("Validated {} tables in database {}", plans.size(), catalog);
                if (!execute) {
                    LOG.info("Validation only: no rows updated. Use --execute to apply masking.");
                    return;
                }
                for (TablePlan plan : plans) {
                    long rows = processTable(conn, plan, batchSize, key);
                    conn.commit();
                    LOG.info("Committed {} row updates in {}", rows, plan.table.sql());
                }
            } catch (Exception failure) {
                try {
                    conn.rollback();
                } catch (SQLException rollbackFailure) {
                    failure.addSuppressed(rollbackFailure);
                }
                LOG.error("Run failed; rollback attempted for current table. Earlier commits remain.");
                throw failure; // Non-zero exit status; do not report success after an error.
            }
        } finally {
            if (key != null) Arrays.fill(key, (byte) 0);
        }
    }

    // 1) Excel mapping. No uppercasing: ASE may use a case-sensitive sort order.
    static Map<TableId, Set<String>> readExcelMapping(String path, String defaultOwner)
            throws IOException {
        Map<TableId, Set<String>> map = new LinkedHashMap<>();
        DataFormatter formatter = new DataFormatter(Locale.ROOT);
        try (InputStream in = new FileInputStream(path);
             Workbook workbook = WorkbookFactory.create(in)) {
            if (workbook.getNumberOfSheets() == 0) throw new IOException("Workbook has no sheets");
            boolean first = true;
            for (Row row : workbook.getSheetAt(0)) {
                String table = getCellString(row.getCell(0), formatter);
                String column = getCellString(row.getCell(1), formatter);
                if (table.isEmpty() && column.isEmpty()) continue;
                if (first && (table.equalsIgnoreCase("table") || table.equalsIgnoreCase("table_name"))
                        && (column.equalsIgnoreCase("column") || column.equalsIgnoreCase("column_name"))) {
                    first = false;
                    continue;
                }
                first = false;
                if (table.isEmpty() || column.isEmpty()) {
                    throw new IOException("Missing table/column at Excel row " + (row.getRowNum() + 1));
                }
                String[] parts = table.split("\\.", -1);
                if (parts.length > 2) throw new IOException("Use table or owner.table: " + table);
                TableId id = new TableId(parts.length == 2 ? parts[0].trim() : defaultOwner,
                        parts[parts.length - 1].trim());
                id.sql(); // Validate identifiers before building any SQL.
                quote(column);
                map.computeIfAbsent(id, ignored -> new LinkedHashSet<>()).add(column);
            }
        }
        if (map.isEmpty()) throw new IOException("Excel mapping is empty");
        return map;
    }

    private static String getCellString(Cell cell, DataFormatter formatter) throws IOException {
        if (cell == null) return "";
        if (cell.getCellType() == CellType.FORMULA || cell.getCellType() == CellType.ERROR) {
            throw new IOException("Mapping must contain literal table/column names, not formulas/errors");
        }
        return formatter.formatCellValue(cell).trim();
    }

    // Resolve ASE user-defined aliases through their storage type in systypes.
    private static Map<Integer, String> fetchBaseTypes(Connection conn) throws SQLException {
        Map<Integer, String> types = new HashMap<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("select type, name from dbo.systypes order by usertype")) {
            while (rs.next()) {
                String name = rs.getString(2).trim().toLowerCase(Locale.ROOT);
                if (TEXT_TYPES.contains(name) || NUMERIC_TYPES.contains(name)) {
                    types.putIfAbsent(rs.getInt(1), name);
                }
            }
        }
        return types;
    }

    // 2) Metadata and keys. All catalog reads stay in the URL's current database.
    private static TablePlan validateTable(Connection conn, String catalog, TableId table,
                                           Set<String> requested, Map<Integer, String> baseTypes)
            throws SQLException {
        Map<String, ColumnMeta> all = fetchColumnMetadata(conn, table, baseTypes);
        if (all.isEmpty()) throw new SQLException("Table not found/visible: " + table.sql());
        List<String> pk = fetchPrimaryKeyColumns(conn, catalog, table);
        if (pk.isEmpty()) {
            throw new SQLException("No declared primary key for " + table.sql()
                    + ". ASE has no Oracle ROWID fallback here; define an appropriate key first.");
        }
        for (String name : pk) {
            if (!all.containsKey(name)) throw new SQLException("PK metadata mismatch: " + table.sql());
        }
        Set<String> protectedColumns = new HashSet<>(pk);
        DatabaseMetaData db = conn.getMetaData();
        try (ResultSet rs = db.getImportedKeys(catalog, table.owner, table.name)) {
            while (rs.next()) protectedColumns.add(rs.getString("FKCOLUMN_NAME"));
        }
        try (ResultSet rs = db.getExportedKeys(catalog, table.owner, table.name)) {
            while (rs.next()) protectedColumns.add(rs.getString("PKCOLUMN_NAME"));
        }
        List<ColumnMeta> masks = new ArrayList<>();
        for (String name : requested) {
            ColumnMeta meta = all.get(name);
            if (meta == null) throw new SQLException("Unknown column (check case): " + table.sql() + "." + name);
            if (protectedColumns.contains(name)) {
                throw new SQLException("PK/FK column needs coordinated masking: " + table.sql() + "." + name);
            }
            if ((meta.status & 128) != 0 || (meta.status2 & (16 | 32 | 64 | 128)) != 0) {
                throw new SQLException("Identity/computed/encrypted column is not supported: " + name);
            }
            if (!TEXT_TYPES.contains(meta.dataType) && !NUMERIC_TYPES.contains(meta.dataType)) {
                throw new SQLException("Unsupported datatype " + meta.declaredType + " for " + table.sql() + "." + name);
            }
            if (NUMERIC_TYPES.contains(meta.dataType)) numericDomain(meta); // Validate precision/scale.
            masks.add(meta);
        }
        LOG.info("Validated {}: primary key {}, mask columns {}", table.sql(), pk, requested);
        return new TablePlan(table, pk, masks);
    }

    private static Map<String, ColumnMeta> fetchColumnMetadata(Connection conn, TableId table,
                                                              Map<Integer, String> baseTypes)
            throws SQLException {
        String sql = """
                select c.name, t.name, c.type, c.prec, c.scale, c.status, c.status2
                from dbo.sysobjects o
                join dbo.sysusers u on u.uid = o.uid
                join dbo.syscolumns c on c.id = o.id
                join dbo.systypes t on t.usertype = c.usertype
                where o.type = 'U' and u.name = ? and o.name = ?
                order by c.colid
                """;
        Map<String, ColumnMeta> result = new LinkedHashMap<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, table.owner);
            ps.setString(2, table.name);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String name = rs.getString(1);
                    String declared = rs.getString(2).trim().toLowerCase(Locale.ROOT);
                    String base = TEXT_TYPES.contains(declared) || NUMERIC_TYPES.contains(declared)
                            ? declared : baseTypes.getOrDefault(rs.getInt(3), declared);
                    result.put(name, new ColumnMeta(name, declared, base,
                            rs.getInt(4), rs.getInt(5), rs.getInt(6), rs.getInt(7)));
                }
            }
        }
        return result;
    }

    private static List<String> fetchPrimaryKeyColumns(Connection conn, String catalog, TableId table)
            throws SQLException {
        SortedMap<Integer, String> columns = new TreeMap<>();
        try (ResultSet rs = conn.getMetaData().getPrimaryKeys(catalog, table.owner, table.name)) {
            while (rs.next()) columns.put(rs.getInt("KEY_SEQ"), rs.getString("COLUMN_NAME"));
        }
        return new ArrayList<>(columns.values());
    }

    // 3) Table processing. No live streaming SELECT is held open during UPDATE.
    private static long processTable(Connection conn, TablePlan plan, int batchSize, byte[] key)
            throws SQLException {
        lockTable(conn, plan.table);
        List<Object> lastKey = null;
        long total = 0;
        while (true) {
            List<Map<String, Object>> rows = readPage(conn, plan, batchSize, lastKey);
            if (rows.isEmpty()) return total;
            Map<String, Object> last = rows.get(rows.size() - 1);
            lastKey = plan.pk.stream().map(last::get).collect(Collectors.toList());
            executeBatchUpdate(conn, plan, rows, key);
            total += rows.size();
            LOG.info("Processed {} rows in {} (not yet committed)", total, plan.table.sql());
        }
    }

    private static void lockTable(Connection conn, TableId table) throws SQLException {
        // ASE lock timeout can be informational rather than a thrown SQLException.
        // Capture @@error immediately, and consume the full JDBC result sequence.
        String sql = "lock table " + table.sql() + " in exclusive mode nowait\nselect @@error";
        try (Statement st = conn.createStatement()) {
            boolean result = st.execute(sql);
            Integer lockError = null;
            while (true) {
                if (result) {
                    try (ResultSet rs = st.getResultSet()) {
                        if (rs.next()) lockError = rs.getInt(1);
                    }
                } else if (st.getUpdateCount() == -1) break;
                result = st.getMoreResults();
            }
            if (lockError == null || lockError != 0) {
                throw new SQLException("Could not verify exclusive lock for " + table.sql()
                        + " (ASE error " + lockError + ")");
            }
        }
    }

    static String buildSelectSql(TablePlan plan, int size, boolean hasLastKey) {
        List<String> columns = new ArrayList<>(plan.pk);
        plan.masks.forEach(meta -> columns.add(meta.columnName));
        String sql = "select top " + size + " " + joinQuoted(columns) + " from " + plan.table.sql();
        if (hasLastKey) {
            List<String> alternatives = new ArrayList<>();
            for (int i = 0; i < plan.pk.size(); i++) {
                List<String> parts = new ArrayList<>();
                for (int j = 0; j < i; j++) parts.add(quote(plan.pk.get(j)) + " = ?");
                parts.add(quote(plan.pk.get(i)) + " > ?");
                alternatives.add("(" + String.join(" and ", parts) + ")");
            }
            sql += " where " + String.join(" or ", alternatives);
        }
        return sql + " order by " + joinQuoted(plan.pk);
    }

    private static List<Map<String, Object>> readPage(Connection conn, TablePlan plan, int size,
                                                    List<Object> lastKey) throws SQLException {
        List<Map<String, Object>> rows = new ArrayList<>(size);
        try (PreparedStatement ps = conn.prepareStatement(buildSelectSql(plan, size, lastKey != null))) {
            if (lastKey != null) {
                int index = 1;
                for (int i = 0; i < plan.pk.size(); i++) {
                    for (int j = 0; j <= i; j++) ps.setObject(index++, lastKey.get(j));
                }
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    int index = 1;
                    for (String pk : plan.pk) {
                        Object value = rs.getObject(index++);
                        if (value == null) throw new SQLException("NULL primary key in " + plan.table.sql());
                        row.put(pk, value);
                    }
                    for (ColumnMeta meta : plan.masks) {
                        Object value = TEXT_TYPES.contains(meta.dataType)
                                ? rs.getString(index++) : rs.getBigDecimal(index++);
                        row.put(meta.columnName, value);
                    }
                    rows.add(row);
                }
            }
        }
        return rows;
    }

    private static void executeBatchUpdate(Connection conn, TablePlan plan,
                                           List<Map<String, Object>> rows, byte[] key) throws SQLException {
        String set = plan.masks.stream().map(m -> quote(m.columnName) + " = ?")
                .collect(Collectors.joining(", "));
        String where = plan.pk.stream().map(p -> quote(p) + " = ?")
                .collect(Collectors.joining(" and "));
        try (PreparedStatement ps = conn.prepareStatement(
                "update " + plan.table.sql() + " set " + set + " where " + where)) {
            for (Map<String, Object> row : rows) {
                int index = 1;
                for (ColumnMeta meta : plan.masks) {
                    Object value = maskValue(row.get(meta.columnName), meta, key);
                    if (TEXT_TYPES.contains(meta.dataType)) {
                        // jConnect handles Unicode conversion for unichar/univarchar.
                        ps.setString(index++, (String) value);
                    } else {
                        ps.setBigDecimal(index++, (BigDecimal) value);
                    }
                }
                for (String pk : plan.pk) ps.setObject(index++, row.get(pk));
                ps.addBatch();
            }
            int[] counts = ps.executeBatch();
            if (counts.length != rows.size()) throw new SQLException("Incomplete batch result");
            for (int count : counts) {
                // Strictly require one matched row, including rejection of SUCCESS_NO_INFO.
                if (count != 1) throw new SQLException("Expected one row per UPDATE; JDBC returned " + count);
            }
        }
    }

    // 4) Deterministic masks. HMAC counter output avoids java.util.Random(hashCode()).
    static Object maskValue(Object original, ColumnMeta meta, byte[] key) {
        if (original == null) return null;
        if (TEXT_TYPES.contains(meta.dataType)) return maskText(original.toString(), key);
        if (NUMERIC_TYPES.contains(meta.dataType)) {
            return maskNumber(new BigDecimal(original.toString()), meta, key);
        }
        throw new IllegalArgumentException("Unsupported datatype: " + meta.dataType);
    }

    static String maskText(String source, byte[] key) {
        MaskStream stream = new MaskStream(key, "text", source);
        StringBuilder result = new StringBuilder(source.length());
        while (result.length() < source.length()) {
            int b = stream.nextByte();
            if (b < 248) result.append(ALPHANUM.charAt(b % ALPHANUM.length()));
        }
        return result.toString();
    }

    static BigDecimal maskNumber(BigDecimal source, ColumnMeta meta, byte[] key) {
        NumericDomain d = numericDomain(meta);
        String domain = "number:" + d.minimum + ":" + d.maximum + ":" + d.scale;
        MaskStream stream = new MaskStream(key, domain, source.stripTrailingZeros().toPlainString());
        BigInteger width = d.maximum.subtract(d.minimum).add(BigInteger.ONE);
        int bits = width.bitLength();
        byte[] candidate = new byte[(bits + 7) / 8];
        BigInteger value;
        do {
            for (int i = 0; i < candidate.length; i++) candidate[i] = (byte) stream.nextByte();
            candidate[0] &= (byte) (255 >>> (candidate.length * 8 - bits));
            value = new BigInteger(1, candidate);
        } while (value.compareTo(width) >= 0);
        return new BigDecimal(value.add(d.minimum), d.scale);
    }

    static NumericDomain numericDomain(ColumnMeta meta) {
        return switch (meta.dataType) {
            case "tinyint" -> integerDomain(8, true, 0);
            case "smallint" -> integerDomain(16, false, 0);
            case "int" -> integerDomain(32, false, 0);
            case "bigint" -> integerDomain(64, false, 0);
            case "unsigned smallint" -> integerDomain(16, true, 0);
            case "unsigned int" -> integerDomain(32, true, 0);
            case "unsigned bigint" -> integerDomain(64, true, 0);
            case "smallmoney" -> integerDomain(32, false, 4);
            case "money" -> integerDomain(64, false, 4);
            case "numeric", "decimal" -> {
                if (meta.precision < 1 || meta.precision > 38 || meta.scale < 0 || meta.scale > meta.precision) {
                    throw new IllegalArgumentException("Invalid precision/scale for " + meta.columnName);
                }
                BigInteger max = BigInteger.TEN.pow(meta.precision).subtract(BigInteger.ONE);
                yield new NumericDomain(max.negate(), max, meta.scale);
            }
            // Approximate types have no decimal scale contract. Use a documented finite
            // replacement range [-1,000,000, +1,000,000], with 4 decimal places before
            // ASE float/real rounding, rather than risk NaN/infinity/overflow.
            case "float", "real", "double precision" ->
                    new NumericDomain(new BigInteger("-10000000000"), new BigInteger("10000000000"), 4);
            default -> throw new IllegalArgumentException("Unsupported numeric type: " + meta.dataType);
        };
    }

    private static NumericDomain integerDomain(int bits, boolean unsigned, int scale) {
        BigInteger limit = BigInteger.ONE.shiftLeft(unsigned ? bits : bits - 1);
        return new NumericDomain(unsigned ? BigInteger.ZERO : limit.negate(),
                limit.subtract(BigInteger.ONE), scale);
    }

    private static final class MaskStream {
        private final Mac mac;
        private final byte[] input;
        private byte[] block = new byte[0];
        private int position;
        private int counter;

        MaskStream(byte[] key, String domain, String source) {
            try {
                mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(key, "HmacSHA256"));
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("HmacSHA256 unavailable", e);
            }
            byte[] prefix = domain.getBytes(StandardCharsets.UTF_8);
            byte[] value = source.getBytes(StandardCharsets.UTF_8);
            input = ByteBuffer.allocate(8 + prefix.length + value.length)
                    .putInt(prefix.length).put(prefix).putInt(value.length).put(value).array();
        }

        int nextByte() {
            if (position == block.length) {
                mac.update(input);
                block = mac.doFinal(ByteBuffer.allocate(4).putInt(counter++).array());
                position = 0;
            }
            return block[position++] & 255;
        }
    }

    private static String joinQuoted(Collection<String> names) {
        return names.stream().map(SybaseMasker::quote).collect(Collectors.joining(", "));
    }

    static String quote(String name) {
        // Conservative support for ordinary names; fail rather than interpolate arbitrary SQL.
        if (name == null || !name.matches("[A-Za-z_][A-Za-z0-9_$#]{0,254}")) {
            throw new IllegalArgumentException("Unsupported identifier: " + name);
        }
        return "\"" + name + "\"";
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) throw new IllegalArgumentException("Set " + name);
        return value;
    }

    record TableId(String owner, String name) {
        String sql() { return quote(owner) + "." + quote(name); }
    }

    record ColumnMeta(String columnName, String declaredType, String dataType,
                      int precision, int scale, int status, int status2) { }

    record TablePlan(TableId table, List<String> pk, List<ColumnMeta> masks) { }

    record NumericDomain(BigInteger minimum, BigInteger maximum, int scale) { }
}
