const http = require('http');
const fs = require('fs');
const path = require('path');
const checkConnection = require('./api/check-connection');

const root = __dirname;
const port = Number(process.env.PORT || 3000);

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml'
};

function send(res, statusCode, body, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(statusCode, { 'Content-Type': contentType });
  res.end(body);
}

function createApiResponse(res) {
  return {
    statusCode: 200,
    headers: {},
    setHeader(name, value) {
      this.headers[name] = value;
      res.setHeader(name, value);
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      res.writeHead(this.statusCode, { ...this.headers, 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(payload));
    },
    end(payload = '') {
      res.writeHead(this.statusCode, this.headers);
      res.end(payload);
    }
  };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        req.destroy();
        reject(new Error('Request body too large'));
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

function resolveStaticPath(urlPath) {
  let pathname = decodeURIComponent(urlPath.split('?')[0]);
  if (pathname === '/' || pathname === '/online_tools' ) pathname = '/online_tools/index.html';
  if (pathname.endsWith('/')) pathname += 'index.html';

  let requested = path.resolve(root, '.' + pathname);
  if (!requested.startsWith(root)) return null;
  // no-trailing-slash directory -> serve its index.html (matches Vercel cleanUrls)
  try {
    if (fs.existsSync(requested) && fs.statSync(requested).isDirectory()) {
      requested = path.join(requested, 'index.html');
    } else if (!fs.existsSync(requested) && fs.existsSync(requested + '.html')) {
      requested = requested + '.html';
    }
  } catch (e) {}
  return requested;
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (url.pathname === '/online_tools/api/check-connection' || url.pathname === '/api/check-connection') {
      req.body = await readBody(req);
      return checkConnection(req, createApiResponse(res));
    }

    const filePath = resolveStaticPath(url.pathname);
    if (!filePath || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
      return send(res, 404, 'Not found');
    }

    const ext = path.extname(filePath).toLowerCase();
    send(res, 200, fs.readFileSync(filePath), mimeTypes[ext] || 'application/octet-stream');
  } catch (error) {
    send(res, 500, `Server error: ${error.message}`);
  }
});

server.listen(port, () => {
  console.log(`Local tools server running at http://localhost:${port}`);
  console.log(`Tools home:       http://localhost:${port}/online_tools/`);
  console.log(`Database checker: http://localhost:${port}/online_tools/db-compatibility-checker/`);
});
