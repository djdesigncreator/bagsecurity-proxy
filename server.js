const http = require('http');
const https = require('https');
const crypto = require('crypto');

const ZONE = process.env.STORAGE_ZONE || '';
const PASS = process.env.STORAGE_PASSWORD || '';
const HOST = (process.env.STORAGE_HOST || '').replace(/^https?:\/\//, '').replace(/\/+$/, '');
const CDN = (process.env.CDN_HOST || '').replace(/^https?:\/\//, '').replace(/\/+$/, '');
const SEGREDO = process.env.UPLOAD_SECRET || '';
const CDN_KEY = process.env.CDN_TOKEN_KEY || '';
const BUBBLE_BASE = (process.env.BUBBLE_BASE || '').replace(/\/+$/, '');
const BUBBLE_TOKEN = process.env.BUBBLE_TOKEN || '';
const PORTA = process.env.PORT || 8080;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
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

function limparNome(bruto) {
  return String(bruto || '').trim().replace(/[\/\\<>:"|?*\u0000-\u001F]/g, '').substring(0, 200);
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
    if (total > 2097152) { req.destroy(); return; }
    dados += c;
  });
  req.on('end', function () {
    if (!dados) return cb(null, {});
    try { cb(null, JSON.parse(dados)); }
    catch (e) { cb(e); }
  });
  req.on('error', function (e) { cb(e); });
}

/* ============ ponte para a Data API do Bubble ============ */

function bubble(metodo, caminho, corpo, cb) {
  if (!BUBBLE_BASE || !BUBBLE_TOKEN) {
    return cb(new Error('Data API nao configurada.'));
  }

  const alvo = BUBBLE_BASE + caminho;
  let u;
  try { u = new URL(alvo); } catch (e) { return cb(new Error('URL invalido.')); }

  const payload = corpo ? JSON.stringify(corpo) : null;

  const opcoes = {
    hostname: u.hostname,
    path: u.pathname + u.search,
    method: metodo,
    headers: {
      'Authorization': 'Bearer ' + BUBBLE_TOKEN,
      'Content-Type': 'application/json'
    }
  };
  if (payload) opcoes.headers['Content-Length'] = Buffer.byteLength(payload);

  const pedido = https.request(opcoes, function (r) {
    let texto = '';
    r.on('data', function (c) { texto += c; });
    r.on('end', function () {
      if (r.statusCode < 200 || r.statusCode >= 300) {
        return cb(new Error('Bubble ' + r.statusCode + ': ' + texto.substring(0, 160)));
      }
      if (!texto) return cb(null, {});
      try { cb(null, JSON.parse(texto)); }
      catch (e) { cb(null, {}); }
    });
  });

  pedido.setTimeout(20000, function () { pedido.destroy(new Error('Bubble demorou demasiado.')); });
  pedido.on('error', function (e) { cb(e); });
  if (payload) pedido.write(payload);
  pedido.end();
}

function constraints(lista) {
  return '?constraints=' + encodeURIComponent(JSON.stringify(lista));
}

/* ============ utilizador ============ */

function carregarUtilizador(id, cb) {
  bubble('GET', '/user/' + encodeURIComponent(id), null, function (e, j) {
    if (e) return cb(e);
    const d = (j && j.response) || j;
    if (!d || !d._id) return cb(new Error('Utilizador nao encontrado.'));
    cb(null, {
      id: d._id,
      limite: Number(d['Storage Limit Bytes'] || 0),
      usado: Number(d['Storage Used Bytes'] || 0),
      maxFicheiro: Number(d['Max File Size Bytes'] || 0),
      plano: d['Plan'] || ''
    });
  });
}

/* ============ URL assinado do CDN ============ */

function urlAssinado(caminho, segundos) {
  const limpo = '/' + encodeURI(caminho);
  if (!CDN) return '';
  if (!CDN_KEY) return 'https://' + CDN + limpo;

  const expira = Math.floor(Date.now() / 1000) + (segundos || 3600);
  const base = CDN_KEY + limpo + expira;

  const hash = crypto.createHash('sha256').update(base).digest('base64')
    .replace(/\n/g, '').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  return 'https://' + CDN + limpo + '?token=' + hash + '&expires=' + expira;
}

/* ============ apagar no Bunny Storage ============ */

function apagarNoBunny(caminho, cb) {
  const opcoes = {
    hostname: HOST,
    path: '/' + ZONE + '/' + encodeURI(caminho),
    method: 'DELETE',
    headers: { 'AccessKey': PASS }
  };
  const p = https.request(opcoes, function (r) {
    r.resume();
    r.on('end', function () { cb(null, r.statusCode); });
  });
  p.setTimeout(15000, function () { p.destroy(); });
  p.on('error', function (e) { cb(e); });
  p.end();
}

/* ============ classificar por extensao ============ */

const TIPOS = {
  Video: ['mp4','mov','webm','avi','mkv','m4v','mpg','mpeg','wmv','flv'],
  Image: ['jpg','jpeg','png','gif','svg','webp','bmp','ico','heic','avif'],
  Audio: ['mp3','wav','ogg','m4a','aac','flac','wma'],
  Document: ['pdf','doc','docx','odt','rtf','pages'],
  Spreadsheet: ['xls','xlsx','csv','ods','numbers'],
  Presentation: ['ppt','pptx','odp','key'],
  Archive: ['zip','rar','7z','tar','gz','bz2','iso','dmg'],
  Text: ['txt','md','json','xml','log','yml','yaml']
};

function classificar(ext) {
  const e = String(ext || '').toLowerCase();
  for (const k in TIPOS) {
    if (TIPOS[k].indexOf(e) !== -1) return k;
  }
  return 'Other';
}
