// Database connectivity test with authentication or TCP reachability.
// Auth tests: PostgreSQL-compatible and MySQL-compatible engines.
// TCP tests: engines without a bundled local driver.

const net = require('net');
const dns = require('dns').promises;

// ---------------------------------------------------------------------------
// SSRF guard: visitors supply arbitrary hosts, so block any target that
// resolves to a private, loopback, link-local (incl. cloud metadata), or
// otherwise reserved address. We resolve first and pin the connection to the
// validated IP, which also defends against DNS rebinding and decimal/octal/hex
// IP encodings (we validate whatever the resolver actually returns).
// ---------------------------------------------------------------------------
const BLOCKED_NAMES = new Set([
  'localhost', 'ip6-localhost', 'ip6-loopback', 'metadata.google.internal'
]);

function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const o of parts) {
    if (!/^\d+$/.test(o)) return null;
    const v = Number(o);
    if (v < 0 || v > 255) return null;
    n = (n * 256) + v;
  }
  return n >>> 0;
}

const BLOCKED_V4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4], ['255.255.255.255', 32]
];

function isBlockedIPv4(ip) {
  const n = ipv4ToInt(ip);
  if (n === null) return false;
  return BLOCKED_V4.some(([base, bits]) => {
    const b = ipv4ToInt(base);
    const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    return (n & mask) === (b & mask);
  });
}

function expandIPv6(ip) {
  let s = ip.split('%')[0]; // drop zone id
  let embeddedV4 = null;
  const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    embeddedV4 = v4[1];
    const n = ipv4ToInt(embeddedV4);
    if (n === null) return null;
    s = s.slice(0, s.length - embeddedV4.length)
      + ((n >>> 16) & 0xffff).toString(16) + ':' + (n & 0xffff).toString(16);
  }
  let groups;
  if (s.includes('::')) {
    const [left, right] = s.split('::');
    const l = left ? left.split(':') : [];
    const r = right ? right.split(':') : [];
    const missing = 8 - (l.length + r.length);
    if (missing < 0) return null;
    groups = [...l, ...Array(missing).fill('0'), ...r];
  } else {
    groups = s.split(':');
  }
  if (groups.length !== 8) return null;
  const ints = groups.map(g => (g === '' ? 0 : parseInt(g, 16)));
  if (ints.some(x => Number.isNaN(x) || x < 0 || x > 0xffff)) return null;
  return { ints, embeddedV4 };
}

function isBlockedIPv6(ip) {
  const parsed = expandIPv6(ip);
  if (!parsed) return false;
  const { ints, embeddedV4 } = parsed;
  const isV4Mapped = ints[0] === 0 && ints[1] === 0 && ints[2] === 0 &&
    ints[3] === 0 && ints[4] === 0 && ints[5] === 0xffff;
  const isNat64 = ints[0] === 0x64 && ints[1] === 0xff9b &&
    ints[2] === 0 && ints[3] === 0 && ints[4] === 0 && ints[5] === 0;
  if ((isV4Mapped || isNat64) && embeddedV4) return isBlockedIPv4(embeddedV4);
  if (ints.every(x => x === 0)) return true;                       // ::
  if (ints.slice(0, 7).every(x => x === 0) && ints[7] === 1) return true; // ::1
  const first = ints[0];
  if ((first & 0xfe00) === 0xfc00) return true;                    // fc00::/7 ULA
  if ((first & 0xffc0) === 0xfe80) return true;                    // fe80::/10 link-local
  if ((first & 0xff00) === 0xff00) return true;                    // ff00::/8 multicast
  return false;
}

function isBlockedIp(ip) {
  if (net.isIPv4(ip)) return isBlockedIPv4(ip);
  if (net.isIPv6(ip)) return isBlockedIPv6(ip);
  return false;
}

function blockError(message) {
  const e = new Error(message);
  e.ssrf = true;
  return e;
}

// Resolves the host, rejects any private/reserved target, and returns the
// validated IP to connect to (pinned). Throws { ssrf:true } if blocked,
// { dnsFail:true } if it cannot be resolved.
async function resolveAndValidate(cleanHost) {
  const lowered = cleanHost.toLowerCase();
  if (!lowered) { const e = new Error('empty host'); e.dnsFail = true; throw e; }
  if (BLOCKED_NAMES.has(lowered) ||
      lowered.endsWith('.localhost') || lowered.endsWith('.local') ||
      lowered.endsWith('.internal') || lowered.endsWith('.lan')) {
    throw blockError(`Target "${cleanHost}" is a reserved or internal name and is blocked for security.`);
  }

  let addresses;
  if (net.isIP(cleanHost)) {
    addresses = [cleanHost];
  } else {
    let resolved;
    try {
      resolved = await dns.lookup(cleanHost, { all: true });
    } catch (err) {
      const e = new Error('resolution failed');
      e.dnsFail = true;
      throw e;
    }
    addresses = resolved.map(r => r.address);
    if (!addresses.length) { const e = new Error('no records'); e.dnsFail = true; throw e; }
  }

  for (const addr of addresses) {
    if (isBlockedIp(addr)) {
      throw blockError(`Target "${cleanHost}" resolves to a private or reserved address (${addr}) and is blocked for security.`);
    }
  }
  return addresses[0]; // pinned, validated IP
}

const DEFAULT_PORTS = {
  postgresql: 5432,
  cockroachdb: 26257,
  redshift: 5439,
  mysql: 3306,
  mariadb: 3306,
  snowflake: 443,
  clickhouse: 8123,
  databricks: 443,
  mssql: 1433,
  oracle: 1521,
  mongodb: 27017
};

let pg, mysql2;
try { pg = require('pg'); } catch(e) { pg = null; }
try { mysql2 = require('mysql2/promise'); } catch(e) { mysql2 = null; }

function displayEngine(dbtype) {
  const names = {
    postgresql: 'PostgreSQL',
    cockroachdb: 'CockroachDB',
    redshift: 'Amazon Redshift',
    mysql: 'MySQL',
    mariadb: 'MariaDB',
    snowflake: 'Snowflake',
    clickhouse: 'ClickHouse',
    databricks: 'Databricks SQL',
    mssql: 'SQL Server',
    oracle: 'Oracle',
    mongodb: 'MongoDB'
  };
  return names[dbtype] || dbtype || 'unknown';
}

function isNetworkError(err) {
  return ['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT', 'EHOSTUNREACH', 'ENETUNREACH'].includes(err.code);
}

function shouldRetryWithSsl(err) {
  const message = String(err.message || '').toLowerCase();
  return err.code === 'HANDSHAKE_SSL_ERROR' ||
    message.includes('ssl') ||
    message.includes('secure transport') ||
    message.includes('encryption required');
}

async function testPostgreSQL(host, connectHost, port, user, password, database, dbtype) {
  let client;
  let usedSsl = false;

  async function connect(useSsl) {
    const config = {
      host: connectHost,
      port: port || DEFAULT_PORTS[dbtype] || 5432,
      user: user || 'postgres',
      password: password || '',
      database: database || 'postgres',
      connectionTimeoutMillis: 8000,
      query_timeout: 5000
    };
    if (useSsl) config.ssl = { rejectUnauthorized: false };
    client = new pg.Client(config);
    await client.connect();
    usedSsl = useSsl;
  }

  try {
    try {
      await connect(false);
    } catch (err) {
      try { if (client) await client.end(); } catch(e) {}
      if (!shouldRetryWithSsl(err)) throw err;
      await connect(true);
    }

    const versionRes = await client.query('SELECT version()');
    const dbList = await client.query(
      "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname LIMIT 20"
    );
    const tableCount = database ? await client.query(
      "SELECT COUNT(*) AS cnt FROM information_schema.tables WHERE table_schema = 'public'"
    ) : null;

    await client.end();

    return {
      testType: 'auth',
      reachable: true,
      authenticated: true,
      engine: displayEngine(dbtype),
      version: versionRes.rows[0].version.split(',')[0],
      databases: dbList.rows.map(r => r.datname),
      tables: tableCount ? parseInt(tableCount.rows[0].cnt, 10) : null,
      ssl: usedSsl,
      message: `Successfully connected and authenticated to ${displayEngine(dbtype)}.`
    };
  } catch (err) {
    try { if (client) await client.end(); } catch(e) {}
    return {
      testType: 'auth',
      reachable: !isNetworkError(err),
      authenticated: false,
      engine: displayEngine(dbtype),
      error: err.code || 'AUTH_FAILED',
      message: formatPgError(err, host, port)
    };
  }
}

function formatPgError(err, host, port) {
  const code = err.code;
  if (code === '28P01') return 'Authentication failed: invalid password for user. Check your username and password.';
  if (code === '3D000') return 'Database does not exist. Check the database name.';
  if (code === '28000') return 'Authentication failed: user not allowed. Check pg_hba.conf.';
  if (code === 'ECONNREFUSED') return `Connection refused at ${host}:${port}. Is the database running and accepting connections?`;
  if (code === 'ENOTFOUND') return `Host not found: "${host}". Check the hostname.`;
  if (code === 'ETIMEDOUT') return `Connection timed out. Check firewall settings for port ${port}.`;
  return `Connection error: ${err.message || err.code || 'Unknown error'}`;
}

async function testMySQL(host, connectHost, port, user, password, database, dbtype) {
  let conn;
  let usedSsl = false;

  async function connect(useSsl) {
    const config = {
      host: connectHost,
      port: port || 3306,
      user: user || 'root',
      password: password || '',
      database: database || undefined,
      connectTimeout: 8000
    };
    if (useSsl) config.ssl = { rejectUnauthorized: false };
    conn = await mysql2.createConnection(config);
    usedSsl = useSsl;
  }

  try {
    try {
      await connect(false);
    } catch (err) {
      try { if (conn) await conn.end(); } catch(e) {}
      if (!shouldRetryWithSsl(err)) throw err;
      await connect(true);
    }

    const [versionRows] = await conn.execute('SELECT VERSION() AS v');
    const [dbRows] = await conn.execute('SHOW DATABASES');
    let tableCount = null;
    if (database) {
      const [tblRows] = await conn.execute(
        'SELECT COUNT(*) AS cnt FROM information_schema.tables WHERE table_schema = ?',
        [database]
      );
      tableCount = tblRows[0].cnt;
    }

    await conn.end();

    return {
      testType: 'auth',
      reachable: true,
      authenticated: true,
      engine: displayEngine(dbtype),
      version: versionRows[0].v,
      databases: dbRows.map(r => r.Database).filter(d => !['information_schema','mysql','performance_schema','sys'].includes(d)),
      tables: tableCount,
      ssl: usedSsl,
      message: `Successfully connected and authenticated to ${displayEngine(dbtype)}.`
    };
  } catch (err) {
    try { if (conn) await conn.end(); } catch(e) {}
    return {
      testType: 'auth',
      reachable: !isNetworkError(err),
      authenticated: false,
      engine: displayEngine(dbtype),
      error: err.code || 'AUTH_FAILED',
      message: formatMysqlError(err, host, port)
    };
  }
}

function formatMysqlError(err, host, port) {
  const code = err.code;
  if (code === 'ER_ACCESS_DENIED_ERROR') return 'Access denied for user. Check username and password.';
  if (code === 'ER_BAD_DB_ERROR') return 'Database does not exist. Check the database name.';
  if (code === 'ECONNREFUSED') return `Connection refused at ${host}:${port}. Is the database running?`;
  if (code === 'ENOTFOUND') return `Host not found: "${host}".`;
  if (code === 'ETIMEDOUT') return `Connection timed out. Check firewall for port ${port}.`;
  if (err.message && err.message.includes('SSL')) return `SSL error: ${err.message}. Try without SSL or check certificates.`;
  return `Connection error: ${err.message || err.code || 'Unknown error'}`;
}

function testTcp(host, connectHost, port, dbtype) {
  const startedAt = Date.now();
  const engine = displayEngine(dbtype);

  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    function finish(result) {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({
        testType: 'tcp',
        engine,
        host,
        port,
        latencyMs: Date.now() - startedAt,
        ...result
      });
    }

    socket.setTimeout(8000);
    socket.once('connect', () => {
      finish({
        reachable: true,
        authenticated: false,
        message: `TCP connection to ${engine} endpoint ${host}:${port} succeeded. This confirms network reachability only; it does not validate credentials, schemas, or query permissions.`
      });
    });
    socket.once('timeout', () => {
      finish({
        reachable: false,
        authenticated: false,
        error: 'ETIMEDOUT',
        message: `TCP connection to ${host}:${port} timed out. Check firewall rules, allowlists, VPN/private network access, and whether the service listens on this port.`
      });
    });
    socket.once('error', (err) => {
      finish({
        reachable: false,
        authenticated: false,
        error: err.code || 'TCP_ERROR',
        message: formatTcpError(err, host, port, engine)
      });
    });
    socket.connect(port, connectHost);
  });
}

function formatTcpError(err, host, port, engine) {
  if (err.code === 'ECONNREFUSED') return `Connection refused at ${host}:${port}. ${engine} may not be running on that port, or the endpoint may require a different port.`;
  if (err.code === 'ENOTFOUND') return `Host not found: "${host}". Check the endpoint hostname.`;
  if (err.code === 'EHOSTUNREACH' || err.code === 'ENETUNREACH') return `Network cannot reach ${host}:${port}. Check VPN, private networking, and firewall access.`;
  if (err.code === 'ETIMEDOUT') return `Connection timed out. Check firewall and allowlist settings for port ${port}.`;
  return `TCP connection error for ${engine}: ${err.message || err.code || 'Unknown error'}`;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Use POST' });

  try {
    const { host, port, dbtype, user, password, database } = req.body || {};

    if (!host?.trim()) {
      return res.status(400).json({ error: 'Host is required' });
    }

    const cleanHost = host.trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    const actualPort = Number(port) || DEFAULT_PORTS[dbtype] || 5432;

    // SSRF guard: resolve + reject private/reserved targets, then pin the
    // connection to the validated IP.
    let connectHost;
    try {
      connectHost = await resolveAndValidate(cleanHost);
    } catch (err) {
      if (err.ssrf) {
        return res.status(400).json({
          reachable: false,
          authenticated: false,
          engine: displayEngine(dbtype),
          host: cleanHost,
          port: actualPort,
          error: 'BLOCKED_TARGET',
          message: err.message
        });
      }
      // could not resolve -> treat as a normal host-not-found result
      return res.status(200).json({
        testType: 'auth',
        reachable: false,
        authenticated: false,
        engine: displayEngine(dbtype),
        host: cleanHost,
        port: actualPort,
        error: 'ENOTFOUND',
        message: `Host not found: "${cleanHost}". Check the hostname.`
      });
    }

    console.log(`Testing ${dbtype}://${cleanHost}:${actualPort}/${database || ''}`);

    let result;
    if ((dbtype === 'postgresql' || dbtype === 'redshift' || dbtype === 'cockroachdb') && pg) {
      result = await testPostgreSQL(cleanHost, connectHost, actualPort, user, password, database, dbtype);
    } else if ((dbtype === 'mysql' || dbtype === 'mariadb') && mysql2) {
      result = await testMySQL(cleanHost, connectHost, actualPort, user, password, database, dbtype);
    } else if (['snowflake', 'clickhouse', 'databricks', 'mssql', 'oracle', 'mongodb'].includes(dbtype)) {
      result = await testTcp(cleanHost, connectHost, actualPort, dbtype);
    } else {
      result = {
        testType: 'unsupported',
        reachable: false,
        authenticated: false,
        engine: displayEngine(dbtype),
        host: cleanHost,
        port: actualPort,
        message: `This checker does not support ${displayEngine(dbtype)} yet. Use a database with a host and port, or connect through the InfiniSynapse platform setup flow.`
      };
    }

    result.host = cleanHost;
    result.port = actualPort;
    return res.status(200).json(result);
  } catch (err) {
    console.error('API error:', err);
    return res.status(500).json({
      reachable: false,
      authenticated: false,
      error: 'SERVER_ERROR',
      message: 'Internal server error: ' + (err.message || '')
    });
  }
};

// Exposed for local testing only; Vercel invokes the default function export.
module.exports.__test = { isBlockedIp, resolveAndValidate };