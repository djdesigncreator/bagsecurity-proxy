const http = require('http');
const https = require('https');
const crypto = require('crypto');

const ZONE = process.env.STORAGE_ZONE || '';
const PASS = process.env.STORAGE_PASSWORD || '';
const HOST = (process.env.STORAGE_HOST || '').replace(/^https?:\/\//, '').replace(/\/+$/, '');
const CDN = (process.env.CDN_HOST || '').replace(/^https?:\/\//, '').replace(/\/+$/, '');
const SEGREDO = process.env.UPLOAD_SECRET || '';
const PORTA = process.env.PORT || 8080;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, PUT, OPTIONS',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Max-Age': '86400'
};

function responder(res, status, obj) {
  const h = Object.assign({}, CORS, { 'Content-Type': 'application/json' });
  res.writeHead(status, h);
  res.end(JSON.stringify(obj));
}

function limpar(bruto) {
  return String(bruto || '').split('/')
    .map(function (p) { return p.trim(); })
    .filter(function (p) { return p && p !== '.' && p !== '..'; })
    .map(function (p) { return p.replace(/[^\w.\-]/g, '_'); })
    .join('/');
}

function assinar(base) {
  return crypto.createHmac('sha256', SEGREDO).update(base).digest('hex');
}

function iguais(a, b) {
  if (a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); }
  catch (e) { return false; }
}

function lerJson(req, cb) {
  let dados = '';
  let total = 0;
  req.on('data', function (c) {
    total += c.length;
    if (total > 1048576) { req.destroy(); return; }
    dados += c;
  });
  req.on('end', function () {
    try { cb(null, JSON.parse(dados)); }
    catch (e) { cb(e); }
  });
  req.on('error', function (e) { cb(e); });
}

const servidor = http.createServer(function (req, res) {

  const url = new URL(req.url, 'http://localhost');

  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS);
    res.end();
    return;
  }

  if (url.pathname === '/' || url.pathname === '') {
    responder(res, 200, {
      servico: 'bagsecurity-proxy',
      versao: 'container-1',
      pronto: Boolean(ZONE && PASS && HOST && SEGREDO)
    });
    return;
  }

  if (url.pathname === '/token' && req.method === 'POST') {
    if (!SEGREDO) { responder(res, 500, { erro: 'Configuracao incompleta.' }); return; }

    lerJson(req, function (err, p) {
      if (err || !p) { responder(res, 400, { erro: 'JSON invalido.' }); return; }

      const nome = limpar(p.name);
      const tamanho = parseInt(String(p.size || '0').replace(/[^0-9]/g, ''), 10);
      const pasta = limpar(p.folder);
      const dono = limpar(p.owner);
      const livre = parseInt(String(p.available || '0').replace(/[^0-9]/g, ''), 10);

      if (!nome) { responder(res, 400, { erro: 'Nome em falta.' }); return; }
      if (!tamanho || tamanho <= 0) { responder(res, 400, { erro: 'Tamanho invalido.' }); return; }
      if (!dono) { responder(res, 403, { erro: 'Utilizador em falta.' }); return; }
      if (livre > 0 && tamanho > livre) { responder(res, 403, { erro: 'Sem espaco suficiente.' }); return; }

      const unico = Date.now() + '-' + Math.floor(Math.random() * 100000) + '-' + nome;
      const caminho = dono + (pasta ? '/' + pasta : '') + '/' + unico;
      const expira = Math.floor(Date.now() / 1000) + 7200;
      const token = expira + '.' + tamanho + '.' + assinar(caminho + '|' + expira + '|' + tamanho);

      responder(res, 200, { ok: true, token: token, path: caminho, expires: expira });
    });
    return;
  }

  if (url.pathname === '/upload' && (req.method === 'POST' || req.method === 'PUT')) {

    if (!ZONE || !PASS || !HOST || !SEGREDO) {
      responder(res, 500, { erro: 'Configuracao incompleta.' });
      return;
    }

    const token = req.headers['x-bsu-token'] || '';
    const caminho = limpar(req.headers['x-bsu-path'] || '');
    const tipo = req.headers['x-bsu-type'] || 'application/octet-stream';

    if (!token) { responder(res, 403, { erro: 'Token em falta.' }); return; }
    if (!caminho) { responder(res, 400, { erro: 'Caminho em falta.' }); return; }

    const partes = String(token).split('.');
    if (partes.length !== 3) { responder(res, 403, { erro: 'Token mal formado.' }); return; }

    const expira = Number(partes[0]);
    const tamanho = Number(partes[1]);
    const recebida = partes[2];

    if (!expira || !tamanho) { responder(res, 403, { erro: 'Token mal formado.' }); return; }
    if (Math.floor(Date.now() / 1000) > expira) { responder(res, 403, { erro: 'Token expirado.' }); return; }

    if (!iguais(recebida, assinar(caminho + '|' + expira + '|' + tamanho))) {
      responder(res, 403, { erro: 'Token invalido.' });
      return;
    }

    const opcoes = {
      hostname: HOST,
      path: '/' + ZONE + '/' + encodeURI(caminho),
      method: 'PUT',
      headers: { 'AccessKey': PASS, 'Content-Type': tipo }
    };

    if (req.headers['content-length']) {
      opcoes.headers['Content-Length'] = req.headers['content-length'];
    } else {
      opcoes.headers['Transfer-Encoding'] = 'chunked';
    }

    const pedido = https.request(opcoes, function (bunny) {
      let corpo = '';
      bunny.on('data', function (c) { corpo += c; });
      bunny.on('end', function () {
        if (bunny.statusCode !== 201 && bunny.statusCode !== 200) {
          responder(res, 502, {
            erro: 'Bunny respondeu ' + bunny.statusCode,
            detalhe: String(corpo).substring(0, 200)
          });
          return;
        }
        responder(res, 200, {
          ok: true,
          caminho: caminho,
          cdn_url: CDN ? 'https://' + CDN + '/' + encodeURI(caminho) : ''
        });
      });
    });

    pedido.on('error', function (e) {
      responder(res, 502, { erro: 'Falha ao contactar o Bunny.', detalhe: String(e.message) });
    });

    req.on('error', function () { pedido.destroy(); });

    req.pipe(pedido);
    return;
  }

  responder(res, 404, { erro: 'Caminho desconhecido.' });
});

servidor.timeout = 0;
servidor.headersTimeout = 0;
servidor.requestTimeout = 0;

servidor.listen(PORTA, function () {
  console.log('bagsecurity-proxy a escutar na porta ' + PORTA);
});
