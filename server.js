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

const STREAM_LIB = String(process.env.STREAM_LIBRARY || '').trim();
const STREAM_KEY = String(process.env.STREAM_KEY || '').trim();
const STREAM_CDN = (process.env.STREAM_CDN || '').replace(/^https?:\/\//, '').replace(/\/+$/, '');

const OO_URL = (process.env.ONLYOFFICE_URL || '').replace(/\/+$/, '');
const OO_SECRET = String(process.env.ONLYOFFICE_SECRET || '').trim();
const SELF_URL = (process.env.SELF_URL || '').replace(/\/+$/, '');

const MOZ_WALLET = String(process.env.MOZ_WALLET || '').trim();
const WEBHOOK_SECRET = String(process.env.WEBHOOK_SECRET || '').trim();

const PORTA = process.env.PORT || 8080;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Max-Age': '86400'
};

function responder(res, status, obj) {
  res.writeHead(status, Object.assign({}, CORS, { 'Content-Type': 'application/json' }));
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

/* ============ construtor de ZIP ============ */

let TABELA_CRC = null;
function tabelaCrc() {
  if (TABELA_CRC) return TABELA_CRC;
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c;
  }
  TABELA_CRC = t;
  return t;
}

function crc32(buf) {
  const t = tabelaCrc();
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = t[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function criarZip(ficheiros) {
  const locais = [];
  const centrais = [];
  let posicao = 0;

  ficheiros.forEach(function (f) {
    const nome = Buffer.from(f.nome, 'utf8');
    const dados = Buffer.isBuffer(f.dados) ? f.dados : Buffer.from(f.dados, 'utf8');
    const soma = crc32(dados);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034B50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0, 12);
    local.writeUInt32LE(soma, 14);
    local.writeUInt32LE(dados.length, 18);
    local.writeUInt32LE(dados.length, 22);
    local.writeUInt16LE(nome.length, 26);
    local.writeUInt16LE(0, 28);

    locais.push(local, nome, dados);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014B50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0, 14);
    central.writeUInt32LE(soma, 16);
    central.writeUInt32LE(dados.length, 20);
    central.writeUInt32LE(dados.length, 24);
    central.writeUInt16LE(nome.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(posicao, 42);

    centrais.push(central, nome);
    posicao += 30 + nome.length + dados.length;
  });

  const corpoLocal = Buffer.concat(locais);
  const corpoCentral = Buffer.concat(centrais);

  const fim = Buffer.alloc(22);
  fim.writeUInt32LE(0x06054B50, 0);
  fim.writeUInt16LE(0, 4);
  fim.writeUInt16LE(0, 6);
  fim.writeUInt16LE(ficheiros.length, 8);
  fim.writeUInt16LE(ficheiros.length, 10);
  fim.writeUInt32LE(corpoCentral.length, 12);
  fim.writeUInt32LE(corpoLocal.length, 16);
  fim.writeUInt16LE(0, 20);

  return Buffer.concat([corpoLocal, corpoCentral, fim]);
}

/* ============ documentos Office vazios ============ */

const XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>';
const NS_REL = 'http://schemas.openxmlformats.org/package/2006/relationships';
const NS_OFF = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';

function rels(lista) {
  return XML + '<Relationships xmlns="' + NS_REL + '">'
    + lista.map(function (r) {
      return '<Relationship Id="' + r.id + '" Type="' + r.tipo + '" Target="' + r.alvo + '"/>';
    }).join('')
    + '</Relationships>';
}

const TEMA = XML
  + '<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Bag">'
  + '<a:themeElements>'
  + '<a:clrScheme name="Bag">'
  + '<a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1>'
  + '<a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1>'
  + '<a:dk2><a:srgbClr val="14582A"/></a:dk2>'
  + '<a:lt2><a:srgbClr val="F4F8F1"/></a:lt2>'
  + '<a:accent1><a:srgbClr val="7AC423"/></a:accent1>'
  + '<a:accent2><a:srgbClr val="1E6B33"/></a:accent2>'
  + '<a:accent3><a:srgbClr val="D08700"/></a:accent3>'
  + '<a:accent4><a:srgbClr val="C0562F"/></a:accent4>'
  + '<a:accent5><a:srgbClr val="5B8A20"/></a:accent5>'
  + '<a:accent6><a:srgbClr val="8B8F5F"/></a:accent6>'
  + '<a:hlink><a:srgbClr val="66A81A"/></a:hlink>'
  + '<a:folHlink><a:srgbClr val="5F7565"/></a:folHlink>'
  + '</a:clrScheme>'
  + '<a:fontScheme name="Bag">'
  + '<a:majorFont><a:latin typeface="Calibri Light"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont>'
  + '<a:minorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont>'
  + '</a:fontScheme>'
  + '<a:fmtScheme name="Bag">'
  + '<a:fillStyleLst>'
  + '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
  + '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
  + '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
  + '</a:fillStyleLst>'
  + '<a:lnStyleLst>'
  + '<a:ln w="6350"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>'
  + '<a:ln w="12700"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>'
  + '<a:ln w="19050"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>'
  + '</a:lnStyleLst>'
  + '<a:effectStyleLst>'
  + '<a:effectStyle><a:effectLst/></a:effectStyle>'
  + '<a:effectStyle><a:effectLst/></a:effectStyle>'
  + '<a:effectStyle><a:effectLst/></a:effectStyle>'
  + '</a:effectStyleLst>'
  + '<a:bgFillStyleLst>'
  + '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
  + '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
  + '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
  + '</a:bgFillStyleLst>'
  + '</a:fmtScheme>'
  + '</a:themeElements>'
  + '</a:theme>';

const ARVORE_VAZIA =
  '<p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
  + '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
  + '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree>';

function docxVazio() {
  const tipos = XML
    + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    + '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    + '<Default Extension="xml" ContentType="application/xml"/>'
    + '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    + '</Types>';

  const raiz = rels([
    { id: 'rId1', tipo: NS_OFF + '/officeDocument', alvo: 'word/document.xml' }
  ]);

  const doc = XML
    + '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    + '<w:body><w:p><w:r><w:t xml:space="preserve"></w:t></w:r></w:p>'
    + '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
    + '<w:pgMar w:top="1417" w:right="1417" w:bottom="1417" w:left="1417"/></w:sectPr>'
    + '</w:body></w:document>';

  return criarZip([
    { nome: '[Content_Types].xml', dados: tipos },
    { nome: '_rels/.rels', dados: raiz },
    { nome: 'word/document.xml', dados: doc }
  ]);
}

function xlsxVazio() {
  const tipos = XML
    + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    + '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    + '<Default Extension="xml" ContentType="application/xml"/>'
    + '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    + '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
    + '</Types>';

  const raiz = rels([
    { id: 'rId1', tipo: NS_OFF + '/officeDocument', alvo: 'xl/workbook.xml' }
  ]);

  const livro = XML
    + '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    + 'xmlns:r="' + NS_OFF + '">'
    + '<sheets><sheet name="Folha1" sheetId="1" r:id="rId1"/></sheets></workbook>';

  const livroRels = rels([
    { id: 'rId1', tipo: NS_OFF + '/worksheet', alvo: 'worksheets/sheet1.xml' }
  ]);

  const folha = XML
    + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    + '<sheetData/></worksheet>';

  return criarZip([
    { nome: '[Content_Types].xml', dados: tipos },
    { nome: '_rels/.rels', dados: raiz },
    { nome: 'xl/workbook.xml', dados: livro },
    { nome: 'xl/_rels/workbook.xml.rels', dados: livroRels },
    { nome: 'xl/worksheets/sheet1.xml', dados: folha }
  ]);
}

function pptxVazio() {
  const P = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
    + 'xmlns:r="' + NS_OFF + '" '
    + 'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"';

  const tipos = XML
    + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    + '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    + '<Default Extension="xml" ContentType="application/xml"/>'
    + '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
    + '<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>'
    + '<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>'
    + '<Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
    + '<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>'
    + '</Types>';

  const raiz = rels([
    { id: 'rId1', tipo: NS_OFF + '/officeDocument', alvo: 'ppt/presentation.xml' }
  ]);

  const apresentacao = XML
    + '<p:presentation ' + P + '>'
    + '<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
    + '<p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst>'
    + '<p:sldSz cx="12192000" cy="6858000"/>'
    + '<p:notesSz cx="6858000" cy="9144000"/>'
    + '</p:presentation>';

  const apresRels = rels([
    { id: 'rId1', tipo: NS_OFF + '/slideMaster', alvo: 'slideMasters/slideMaster1.xml' },
    { id: 'rId2', tipo: NS_OFF + '/slide', alvo: 'slides/slide1.xml' },
    { id: 'rId3', tipo: NS_OFF + '/theme', alvo: 'theme/theme1.xml' }
  ]);

  const mestre = XML
    + '<p:sldMaster ' + P + '>'
    + '<p:cSld>' + ARVORE_VAZIA + '</p:cSld>'
    + '<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" '
    + 'accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" '
    + 'hlink="hlink" folHlink="folHlink"/>'
    + '<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>'
    + '</p:sldMaster>';

  const mestreRels = rels([
    { id: 'rId1', tipo: NS_OFF + '/slideLayout', alvo: '../slideLayouts/slideLayout1.xml' },
    { id: 'rId2', tipo: NS_OFF + '/theme', alvo: '../theme/theme1.xml' }
  ]);

  const esquema = XML
    + '<p:sldLayout ' + P + ' type="blank" preserve="1">'
    + '<p:cSld name="Em branco">' + ARVORE_VAZIA + '</p:cSld>'
    + '<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>'
    + '</p:sldLayout>';

  const esquemaRels = rels([
    { id: 'rId1', tipo: NS_OFF + '/slideMaster', alvo: '../slideMasters/slideMaster1.xml' }
  ]);

  const diapositivo = XML
    + '<p:sld ' + P + '>'
    + '<p:cSld>' + ARVORE_VAZIA + '</p:cSld>'
    + '<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>'
    + '</p:sld>';

  const diapoRels = rels([
    { id: 'rId1', tipo: NS_OFF + '/slideLayout', alvo: '../slideLayouts/slideLayout1.xml' }
  ]);

  return criarZip([
    { nome: '[Content_Types].xml', dados: tipos },
    { nome: '_rels/.rels', dados: raiz },
    { nome: 'ppt/presentation.xml', dados: apresentacao },
    { nome: 'ppt/_rels/presentation.xml.rels', dados: apresRels },
    { nome: 'ppt/slideMasters/slideMaster1.xml', dados: mestre },
    { nome: 'ppt/slideMasters/_rels/slideMaster1.xml.rels', dados: mestreRels },
    { nome: 'ppt/slideLayouts/slideLayout1.xml', dados: esquema },
    { nome: 'ppt/slideLayouts/_rels/slideLayout1.xml.rels', dados: esquemaRels },
    { nome: 'ppt/slides/slide1.xml', dados: diapositivo },
    { nome: 'ppt/slides/_rels/slide1.xml.rels', dados: diapoRels },
    { nome: 'ppt/theme/theme1.xml', dados: TEMA }
  ]);
}

function ficheiroVazio(tipo) {
  if (tipo === 'xlsx') return xlsxVazio();
  if (tipo === 'pptx') return pptxVazio();
  return docxVazio();
}

/* ============ JWT do OnlyOffice ============ */

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function jwtAssinar(payload) {
  const cabecalho = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const corpo = b64url(JSON.stringify(payload));
  const base = cabecalho + '.' + corpo;
  const firma = b64url(crypto.createHmac('sha256', OO_SECRET).update(base).digest());
  return base + '.' + firma;
}

function jwtVerificar(token) {
  const partes = String(token || '').split('.');
  if (partes.length !== 3) return null;
  const base = partes[0] + '.' + partes[1];
  const esperada = b64url(crypto.createHmac('sha256', OO_SECRET).update(base).digest());
  if (!iguais(partes[2], esperada)) return null;
  try {
    return JSON.parse(Buffer.from(partes[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
  } catch (e) { return null; }
}

/* ============ Data API do Bubble ============ */

function bubble(metodo, caminho, corpo, cb) {
  if (!BUBBLE_BASE || !BUBBLE_TOKEN) return cb(new Error('Data API nao configurada.'));

  let u;
  try { u = new URL(BUBBLE_BASE + caminho); } catch (e) { return cb(new Error('URL invalido.')); }

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

function buscarTudo(tipo, cs, extra, cb) {
  const out = [];
  function pagina(cursor) {
    const url = tipo + constraints(cs) + '&limit=100&cursor=' + cursor + (extra || '');
    bubble('GET', url, null, function (e, j) {
      if (e) return cb(e);
      const r = (j && j.response) || {};
      const lista = r.results || [];
      lista.forEach(function (x) { out.push(x); });
      if (Number(r.remaining || 0) > 0 && out.length < 3000) return pagina(cursor + lista.length);
      cb(null, out);
    });
  }
  pagina(0);
}

/* procura um utilizador pelo email */
function procurarPorEmail(email, cb) {
  const alvo = String(email || '').toLowerCase().trim();
  if (!alvo) return cb(null, null);
  const c = [{ key: 'email', constraint_type: 'equals', value: alvo }];
  bubble('GET', '/user' + constraints(c) + '&limit=1', null, function (e, j) {
    if (e) return cb(e);
    const lista = (((j || {}).response || {}).results || []);
    cb(null, lista.length ? lista[0] : null);
  });
}

/* ============ Bunny Stream ============ */

function stream(metodo, caminho, corpo, cb) {
  if (!STREAM_LIB || !STREAM_KEY) return cb(new Error('Stream nao configurado.'));

  const payload = corpo ? JSON.stringify(corpo) : null;
  const opcoes = {
    hostname: 'video.bunnycdn.com',
    path: '/library/' + STREAM_LIB + caminho,
    method: metodo,
    headers: { 'AccessKey': STREAM_KEY, 'Content-Type': 'application/json', 'accept': 'application/json' }
  };
  if (payload) opcoes.headers['Content-Length'] = Buffer.byteLength(payload);

  const pedido = https.request(opcoes, function (r) {
    let texto = '';
    r.on('data', function (c) { texto += c; });
    r.on('end', function () {
      if (r.statusCode < 200 || r.statusCode >= 300) {
        return cb(new Error('Stream ' + r.statusCode + ': ' + texto.substring(0, 160)));
      }
      if (!texto) return cb(null, {});
      try { cb(null, JSON.parse(texto)); } catch (e) { cb(null, {}); }
    });
  });

  pedido.setTimeout(20000, function () { pedido.destroy(new Error('Stream demorou demasiado.')); });
  pedido.on('error', function (e) { cb(e); });
  if (payload) pedido.write(payload);
  pedido.end();
}

function assinaturaTus(videoId, expira) {
  return crypto.createHash('sha256')
    .update(STREAM_LIB + STREAM_KEY + expira + videoId).digest('hex');
}

/* ============ MoPayment ============ */

const MOZ_ROTAS = {
  mpesa: '/api/1.1/wf/pagamentorotativompesa',
  emola: '/api/1.1/wf/pagamentorotativoemola'
};

const PREFIXOS = { mpesa: ['84', '85'], emola: ['86', '87'] };

function limparNumero(bruto) {
  let n = String(bruto || '').replace(/[^0-9]/g, '');
  if (n.indexOf('258') === 0) n = n.substring(3);
  return n;
}

function numeroValido(numero, metodo) {
  if (!/^\d{9}$/.test(numero)) return 'O numero deve ter 9 digitos.';
  const pre = numero.substring(0, 2);
  const lista = PREFIXOS[metodo] || [];
  if (lista.indexOf(pre) === -1) {
    return metodo === 'mpesa'
      ? 'Numeros M-Pesa comecam por 84 ou 85.'
      : 'Numeros e-Mola comecam por 86 ou 87.';
  }
  return null;
}

function extrairCod(j) {
  if (!j || typeof j !== 'object') return 0;
  const chaves = ['cod', 'code', 'codigo', 'status_code', 'statusCode'];
  for (let i = 0; i < chaves.length; i++) {
    if (j[chaves[i]] !== undefined && j[chaves[i]] !== null) {
      const n = Number(j[chaves[i]]);
      if (!isNaN(n)) return n;
    }
  }
  if (j.response && typeof j.response === 'object') return extrairCod(j.response);
  return 0;
}

function extrairTexto(j, chaves) {
  if (!j || typeof j !== 'object') return '';
  for (let i = 0; i < chaves.length; i++) {
    const v = j[chaves[i]];
    if (typeof v === 'string' && v) return v;
  }
  if (j.response && typeof j.response === 'object') return extrairTexto(j.response, chaves);
  return '';
}

function sucessoPago(j, cod) {
  if (cod === 200 || cod === 201) return true;
  const estado = String(extrairTexto(j, ['status', 'estado', 'result'])).toLowerCase();
  return estado === 'success' || estado === 'sucesso' || estado === 'ok';
}

function cobrar(metodo, numero, cliente, valor, cb) {
  if (!MOZ_WALLET) return cb(new Error('Carteira de pagamento nao configurada.'));

  const rota = MOZ_ROTAS[metodo];
  if (!rota) return cb(new Error('Metodo de pagamento desconhecido.'));

  const payload = JSON.stringify({
    carteira: MOZ_WALLET,
    numero: String(numero),
    cliente: String(cliente || 'Cliente').substring(0, 80),
    valor: String(valor)
  });

  const pedido = https.request({
    hostname: 'mozpayment.co.mz',
    path: rota,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    }
  }, function (r) {
    let texto = '';
    r.on('data', function (c) { texto += c; });
    r.on('end', function () {
      let j = null;
      try { j = JSON.parse(texto); } catch (e) { j = null; }

      if (!j) {
        return cb(null, {
          ok: false, cod: -1,
          mensagem: 'Resposta ilegivel do sistema de pagamento.',
          transacao: '',
          bruto: 'HTTP ' + r.statusCode + ' | ' + String(texto).substring(0, 700)
        });
      }

      const cod = extrairCod(j);
      cb(null, {
        ok: sucessoPago(j, cod),
        cod: cod,
        mensagem: extrairTexto(j, ['mensagem', 'message', 'detalhe', 'detail', 'erro', 'error']),
        transacao: extrairTexto(j, ['transacao', 'transaction', 'reference', 'referencia', 'id']),
        bruto: 'HTTP ' + r.statusCode + ' | ' + JSON.stringify(j).substring(0, 700)
      });
    });
  });

  pedido.setTimeout(180000, function () {
    pedido.destroy(new Error('O pagamento demorou demasiado. Verifica o teu telemovel.'));
  });
  pedido.on('error', function (e) { cb(e); });
  pedido.write(payload);
  pedido.end();
}

function registarPagamento(u, d, cb) {
  const registo = {
    'User': u.id,
    'Method': d.metodo || '',
    'Phone': d.numero || '',
    'Amount MZN': Number(d.valor || 0),
    'Item Type': d.tipo || '',
    'Item Name': d.nome || '',
    'Item ID': d.itemId || '',
    'Status': d.estado || '',
    'Transaction': d.transacao || '',
    'Message': String(d.mensagem || '').substring(0, 400),
    'Raw': String(d.bruto || '').substring(0, 900)
  };
  bubble('POST', '/payment', registo, function (e, j) { if (cb) cb(e, j); });
}

function somaDias(base, dias) {
  const d = base ? new Date(base) : new Date();
  const agora = new Date();
  const inicio = (isNaN(d.getTime()) || d < agora) ? agora : d;
  return new Date(inicio.getTime() + dias * 86400000).toISOString();
}

/* ============ utilizador ============ */

function diasAte(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (isNaN(d.getTime())) return null;
  return Math.ceil((d.getTime() - Date.now()) / 86400000);
}

function moldarUtilizador(d) {
  const expiraEm = d['Plan Expires'] || '';
  const dias = diasAte(expiraEm);
  const base = Number(d['Storage Limit Bytes'] || 0);
  const extra = Number(d['Extra Storage Bytes'] || 0);
  const limite = base + extra;
  const usado = Number(d['Storage Used Bytes'] || 0);

  return {
    id: d._id,
    nome: d['Full Name'] || 'Utilizador',
    email: d['authentication'] && d['authentication'].email
      ? d['authentication'].email.email : (d['email'] || ''),
    base: base, extra: extra, limite: limite, usado: usado,
    maxFicheiro: Number(d['Max File Size Bytes'] || 0),
    plano: d['Plan'] || '',
    activo: d['Is Active'] !== false,
    expira: expiraEm, dias: dias,
    expirado: dias !== null && dias <= 0,
    excesso: limite > 0 && usado > limite,
    livre: Math.max(0, limite - usado)
  };
}

function carregarUtilizador(id, cb) {
  bubble('GET', '/user/' + encodeURIComponent(id), null, function (e, j) {
    if (e) return cb(e);
    const d = (j && j.response) || j;
    if (!d || !d._id) return cb(new Error('Utilizador nao encontrado.'));
    cb(null, moldarUtilizador(d));
  });
}

function porqueBloqueado(u) {
  if (!u.activo) return 'A tua conta esta suspensa. Fala connosco.';
  if (!u.expira) return 'A tua subscricao nao esta activa. Escolhe um plano para comecares.';
  if (u.expirado) {
    return 'O teu plano expirou. Renova para voltares a enviar ficheiros. '
      + 'Os teus ficheiros continuam acessiveis.';
  }
  return null;
}

/* ============ URL assinado ============ */

function urlAssinado(caminho, segundos) {
  if (!CDN) return '';
  const limpo = '/' + encodeURI(caminho);
  if (!CDN_KEY) return 'https://' + CDN + limpo;

  const expira = Math.floor(Date.now() / 1000) + (segundos || 3600);
  const hash = crypto.createHash('sha256').update(CDN_KEY + limpo + expira).digest('base64')
    .replace(/\n/g, '').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  return 'https://' + CDN + limpo + '?token=' + hash + '&expires=' + expira;
}

/* ============ Bunny Storage ============ */

function apagarNoBunny(caminho, cb) {
  if (!caminho) return cb(null, 404);
  const p = https.request({
    hostname: HOST, path: '/' + ZONE + '/' + encodeURI(caminho),
    method: 'DELETE', headers: { 'AccessKey': PASS }
  }, function (r) {
    r.resume();
    r.on('end', function () { cb(null, r.statusCode); });
  });
  p.setTimeout(15000, function () { p.destroy(); });
  p.on('error', function (e) { cb(e); });
  p.end();
}

function guardarBuffer(conteudo, caminho, tipo, cb) {
  const escrita = https.request({
    hostname: HOST,
    path: '/' + ZONE + '/' + encodeURI(caminho),
    method: 'PUT',
    headers: {
      'AccessKey': PASS,
      'Content-Type': tipo || 'application/octet-stream',
      'Content-Length': conteudo.length
    }
  }, function (b) {
    let corpo = '';
    b.on('data', function (c) { corpo += c; });
    b.on('end', function () {
      if (b.statusCode !== 201 && b.statusCode !== 200) {
        return cb(new Error('Bunny respondeu ' + b.statusCode));
      }
      cb(null, true);
    });
  });
  escrita.setTimeout(60000, function () { escrita.destroy(new Error('Demorou demasiado.')); });
  escrita.on('error', function (e) { cb(e); });
  escrita.write(conteudo);
  escrita.end();
}

/* copia um ficheiro dentro do Bunny */
function copiarNoBunny(origem, destino, cb) {
  const leitura = https.request({
    hostname: HOST,
    path: '/' + ZONE + '/' + encodeURI(origem),
    method: 'GET',
    headers: { 'AccessKey': PASS }
  }, function (r) {
    if (r.statusCode !== 200) {
      r.resume();
      return cb(new Error('Nao foi possivel ler o ficheiro (' + r.statusCode + ').'));
    }

    const escrita = https.request({
      hostname: HOST,
      path: '/' + ZONE + '/' + encodeURI(destino),
      method: 'PUT',
      headers: {
        'AccessKey': PASS,
        'Content-Type': 'application/octet-stream',
        'Transfer-Encoding': 'chunked'
      }
    }, function (b) {
      let corpo = '';
      b.on('data', function (c) { corpo += c; });
      b.on('end', function () {
        if (b.statusCode !== 201 && b.statusCode !== 200) {
          return cb(new Error('Bunny respondeu ' + b.statusCode));
        }
        cb(null, true);
      });
    });

    escrita.on('error', function (e) { cb(e); });
    r.pipe(escrita);
  });

  leitura.setTimeout(180000, function () { leitura.destroy(new Error('Demorou demasiado.')); });
  leitura.on('error', function (e) { cb(e); });
  leitura.end();
}

function guardarDeUrl(origem, caminho, tipo, cb, saltos) {
  saltos = saltos || 0;
  if (saltos > 5) return cb(new Error('Demasiados redireccionamentos.'));

  let u;
  try { u = new URL(origem); } catch (e) { return cb(new Error('URL de origem invalido.')); }

  const cliente = u.protocol === 'http:' ? http : https;

  const leitura = cliente.get({
    hostname: u.hostname,
    port: u.port || undefined,
    path: u.pathname + u.search,
    headers: { 'accept': '*/*' }
  }, function (r) {

    if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) {
      r.resume();
      const seguinte = new URL(r.headers.location, origem).toString();
      return guardarDeUrl(seguinte, caminho, tipo, cb, saltos + 1);
    }

    if (r.statusCode !== 200) {
      r.resume();
      return cb(new Error('Origem respondeu ' + r.statusCode));
    }

    const escrita = https.request({
      hostname: HOST, path: '/' + ZONE + '/' + encodeURI(caminho), method: 'PUT',
      headers: {
        'AccessKey': PASS,
        'Content-Type': tipo || 'application/octet-stream',
        'Transfer-Encoding': 'chunked'
      }
    }, function (b) {
      let corpo = '';
      b.on('data', function (c) { corpo += c; });
      b.on('end', function () {
        if (b.statusCode !== 201 && b.statusCode !== 200) {
          return cb(new Error('Bunny respondeu ' + b.statusCode));
        }
        cb(null, true);
      });
    });

    escrita.on('error', function (e) { cb(e); });
    r.pipe(escrita);
  });

  leitura.setTimeout(120000, function () { leitura.destroy(new Error('Demorou demasiado.')); });
  leitura.on('error', function (e) { cb(e); });
}

/* ============ classificar ============ */

const TIPOS = {
  Video: ['mp4','mov','webm','avi','mkv','m4v','mpg','mpeg','wmv','flv','3gp','ts'],
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

function eVideo(ext) {
  return TIPOS.Video.indexOf(String(ext || '').toLowerCase()) !== -1;
}

/* ============ OnlyOffice: formatos ============ */

const OO_TEXTO = ['docx','doc','odt','rtf','txt','html','epub','fb2','pdf','djvu','xps','md'];
const OO_FOLHA = ['xlsx','xls','ods','csv'];
const OO_SLIDE = ['pptx','ppt','odp'];
const OO_EDITAVEL = ['docx','odt','rtf','txt','xlsx','ods','csv','pptx','odp'];

/* formatos que exigem copia propria ao enviar a outro utilizador */
const PRECISA_COPIA = [
  'docx','doc','odt','rtf','txt','md',
  'xlsx','xls','ods','csv',
  'pptx','ppt','odp'
];

function ooTipo(ext) {
  const e = String(ext || '').toLowerCase();
  if (OO_TEXTO.indexOf(e) !== -1) return 'word';
  if (OO_FOLHA.indexOf(e) !== -1) return 'cell';
  if (OO_SLIDE.indexOf(e) !== -1) return 'slide';
  return '';
}

function ooEditavel(ext) {
  return OO_EDITAVEL.indexOf(String(ext || '').toLowerCase()) !== -1;
}

function precisaCopia(ext) {
  return PRECISA_COPIA.indexOf(String(ext || '').toLowerCase()) !== -1;
}

/* ============ mapear ============ */

function mapear(f) {
  const noStream = f['Storage Type'] === 'Bunny Stream';
  const vid = f['Bunny Video ID'] || '';
  const ext = f['Extension'] || '';

  return {
    id: f._id,
    nome: f['Original Name'] || f['Name'] || '',
    ext: ext,
    tipo: f['File Type'] || 'Other',
    mime: f['MIME Type'] || '',
    tamanho: Number(f['Size Bytes'] || 0),
    caminho: f['Bunny Path'] || '',
    estado: f['Status'] || 'Ready',
    stream: noStream,
    video_id: vid,
    office: Boolean(OO_URL) && !noStream && ooTipo(ext) !== '',
    editavel: Boolean(OO_URL) && !noStream && ooEditavel(ext),
    url: noStream
      ? (STREAM_CDN && vid ? 'https://' + STREAM_CDN + '/' + vid + '/play_720p.mp4' : '')
      : urlAssinado(f['Bunny Path'] || '', 3600),
    player: noStream && vid
      ? 'https://iframe.mediadelivery.net/embed/' + STREAM_LIB + '/' + vid + '?autoplay=false'
      : '',
    thumb: noStream && vid && STREAM_CDN
      ? 'https://' + STREAM_CDN + '/' + vid + '/thumbnail.jpg'
      : (f['File Type'] === 'Image' ? urlAssinado(f['Bunny Path'] || '', 3600) : ''),
    partilhado: f['Is Shared'] === true,
    pasta: f['Folder'] || '',
    criado: f['Created Date'] || '',
    recebido: Boolean(f['Sent By']),
    copia_ligada: f['Shares Storage'] === true
  };
}

/* ============ EMAIL pelo Resend ============ */

const RESEND_KEY = String(process.env.RESEND_KEY || '').trim();
const MAIL_FROM = String(process.env.MAIL_FROM || '').trim();
const APP_URL = (process.env.APP_URL || '').replace(/\/+$/, '');

/* gera um codigo curto, facil de ler e de escrever */
function gerarCodigo() {
  /* sem I, O, 0, 1 para nao confundir */
  const letras = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const numeros = '23456789';
  const bytes = crypto.randomBytes(8);
  let saida = '';
  for (let i = 0; i < 8; i++) {
    const fonte = i < 4 ? letras : numeros;
    saida += fonte[bytes[i] % fonte.length];
  }
  return saida;
}

function escaparHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function enviarEmail(para, assunto, html, texto, cb) {
  if (!RESEND_KEY || !MAIL_FROM) {
    return cb(new Error('Envio de email nao configurado.'));
  }

  const payload = JSON.stringify({
    from: MAIL_FROM,
    to: [String(para)],
    subject: String(assunto),
    html: html,
    text: texto || ''
  });

  const pedido = https.request({
    hostname: 'api.resend.com',
    path: '/emails',
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + RESEND_KEY,
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    }
  }, function (r) {
    let corpo = '';
    r.on('data', function (c) { corpo += c; });
    r.on('end', function () {
      if (r.statusCode < 200 || r.statusCode >= 300) {
        let detalhe = corpo.substring(0, 200);
        try {
          const j = JSON.parse(corpo);
          detalhe = j.message || j.name || detalhe;
        } catch (e) {}
        return cb(new Error('Resend ' + r.statusCode + ': ' + detalhe));
      }
      let id = '';
      try { id = (JSON.parse(corpo) || {}).id || ''; } catch (e) {}
      cb(null, { id: id });
    });
  });

  pedido.setTimeout(20000, function () {
    pedido.destroy(new Error('O envio de email demorou demasiado.'));
  });
  pedido.on('error', function (e) { cb(e); });
  pedido.write(payload);
  pedido.end();
}

/* ---------- modelo do email ---------- */

function moldura(titulo, corpo) {
  return '<div style="margin:0;padding:26px 14px;background:#F4F8F1;'
    + 'font-family:Helvetica,Arial,sans-serif">'

    + '<div style="max-width:520px;margin:0 auto;background:#FFFFFF;'
    + 'border:1px solid #E2EBDC;border-radius:16px;overflow:hidden">'

    /* cabecalho */
    + '<div style="background:#14582A;padding:26px 28px">'
    + '<div style="font-size:21px;font-weight:700;color:#FFFFFF;letter-spacing:-.5px">'
    + 'bag<span style="color:#7AC423">Security</span></div>'
    + '<div style="font-size:11px;color:#8FC474;margin-top:3px">'
    + 'Hospedagem de arquivos segura</div>'
    + '</div>'

    /* corpo */
    + '<div style="padding:30px 28px">'
    + '<div style="font-size:20px;font-weight:700;color:#12281A;'
    + 'margin:0 0 14px;letter-spacing:-.4px">' + titulo + '</div>'
    + corpo
    + '</div>'

    /* rodape */
    + '<div style="padding:20px 28px;background:#F4F8F1;border-top:1px solid #E2EBDC">'
    + '<div style="font-size:12px;color:#5F7565;line-height:1.6">'
    + 'Segurança primeiro, <b style="color:#12281A">hospedagem depois.</b></div>'
    + '<div style="font-size:11px;color:#A8BCA0;margin-top:8px;line-height:1.6">'
    + 'Recebeste este email porque alguém usou este endereço na Bag Security. '
    + 'Se não foste tu, ignora esta mensagem.</div>'
    + '</div>'

    + '</div></div>';
}

function emailCodigo(nome, codigo) {
  const corpo =
    '<p style="font-size:15px;color:#5F7565;line-height:1.7;margin:0 0 22px">'
    + 'Olá ' + escaparHtml(nome) + ', falta só um passo. '
    + 'Escreve este código na página para confirmares o teu email.</p>'

    + '<div style="background:#EEF8E2;border:1px solid #D5EDBB;border-radius:13px;'
    + 'padding:22px;text-align:center;margin:0 0 22px">'
    + '<div style="font-size:11px;color:#66A81A;font-weight:600;'
    + 'letter-spacing:1.4px;text-transform:uppercase;margin-bottom:9px">'
    + 'O teu código</div>'
    + '<div style="font-size:31px;font-weight:700;color:#1E6B33;'
    + 'letter-spacing:7px;font-family:Consolas,Monaco,monospace">'
    + escaparHtml(codigo) + '</div>'
    + '</div>'

    + '<p style="font-size:13.5px;color:#5F7565;line-height:1.7;margin:0">'
    + 'O código é válido durante 30 minutos. '
    + 'Se expirar, podes pedir outro na mesma página.</p>';

  const texto = 'Ola ' + nome + ',\n\n'
    + 'O teu codigo de confirmacao e: ' + codigo + '\n\n'
    + 'Valido durante 30 minutos.\n\n'
    + 'Bag Security';

  return { html: moldura('Confirma o teu email', corpo), texto: texto };
}

function emailBemVindo(nome) {
  const botao = APP_URL
    ? '<div style="margin:0 0 22px">'
      + '<a href="' + APP_URL + '" style="display:inline-block;background:#7AC423;'
      + 'color:#14582A;text-decoration:none;font-size:15px;font-weight:700;'
      + 'padding:14px 30px;border-radius:11px">Abrir a minha conta</a></div>'
    : '';

  const corpo =
    '<p style="font-size:15px;color:#5F7565;line-height:1.7;margin:0 0 22px">'
    + 'Olá ' + escaparHtml(nome) + ', a tua conta está pronta. '
    + 'Tens 200 MB para começares, sem pagar nada.</p>'
    + botao
    + '<div style="border-top:1px solid #E2EBDC;padding-top:20px">'
    + '<div style="font-size:13.5px;color:#12281A;font-weight:600;margin-bottom:12px">'
    + 'O que podes fazer já:</div>'
    + '<div style="font-size:13.5px;color:#5F7565;line-height:1.9">'
    + '&bull; Enviar ficheiros e vídeos, que convertemos automaticamente<br>'
    + '&bull; Criar e editar Word, Excel e PowerPoint no browser<br>'
    + '&bull; Partilhar por link, com prazo e password<br>'
    + '&bull; Enviar ficheiros a quem também tem conta'
    + '</div></div>';

  const texto = 'Ola ' + nome + ',\n\n'
    + 'A tua conta Bag Security esta pronta. Tens 200 MB gratis para comecares.\n\n'
    + (APP_URL ? APP_URL + '\n\n' : '')
    + 'Bag Security';

  return { html: moldura('Conta criada', corpo), texto: texto };
}

function emailAviso(nome, dias) {
  const quando = dias <= 0 ? 'expirou'
    : (dias === 1 ? 'acaba amanhã' : 'acaba dentro de ' + dias + ' dias');

  const botao = APP_URL
    ? '<div style="margin:0 0 22px">'
      + '<a href="' + APP_URL + '" style="display:inline-block;background:#7AC423;'
      + 'color:#14582A;text-decoration:none;font-size:15px;font-weight:700;'
      + 'padding:14px 30px;border-radius:11px">Renovar agora</a></div>'
    : '';

  const corpo =
    '<p style="font-size:15px;color:#5F7565;line-height:1.7;margin:0 0 22px">'
    + 'Olá ' + escaparHtml(nome) + ', o teu plano ' + quando + '.</p>'
    + botao
    + '<p style="font-size:13.5px;color:#5F7565;line-height:1.7;margin:0">'
    + 'Os teus ficheiros continuam acessíveis. Só os envios de ficheiros novos '
    + 'ficam suspensos até renovares.</p>';

  const texto = 'Ola ' + nome + ',\n\n'
    + 'O teu plano Bag Security ' + quando + '.\n'
    + 'Os teus ficheiros continuam acessiveis.\n\n'
    + (APP_URL ? APP_URL + '\n\n' : '')
    + 'Bag Security';

  return { html: moldura('O teu plano ' + quando, corpo), texto: texto };
}

/* limita quantos codigos se podem pedir por hora */
const PEDIDOS = {};

function podePedir(chave) {
  const agora = Date.now();
  const lista = (PEDIDOS[chave] || []).filter(function (t) { return agora - t < 3600000; });
  PEDIDOS[chave] = lista;
  if (lista.length >= 5) return false;
  lista.push(agora);
  return true;
}

/* ============ SERVIDOR ============ */

const servidor = http.createServer(function (req, res) {

  const url = new URL(req.url, 'http://localhost');
  const rota = url.pathname;
  const metodo = req.method.toUpperCase();

  if (metodo === 'OPTIONS') { res.writeHead(204, CORS); res.end(); return; }

  /* ---------- estado ---------- */
  if (rota === '/' || rota === '') {
    return responder(res, 200, {
      servico: 'bagsecurity-proxy',
      versao: 'container-12',
      storage: Boolean(ZONE && PASS && HOST),
      bubble: Boolean(BUBBLE_BASE && BUBBLE_TOKEN),
      cdn_assinado: Boolean(CDN_KEY),
      stream: Boolean(STREAM_LIB && STREAM_KEY && STREAM_CDN),
      office: Boolean(OO_URL && OO_SECRET),
      pagamento: Boolean(MOZ_WALLET),
      envio: true,
      webhook_card: Boolean(WEBHOOK_SECRET)
    });
  }

  /* ---------- planos e pacotes ---------- */
  if (rota === '/plans' && metodo === 'POST') {
    const c = [{ key: 'Is Active', constraint_type: 'equals', value: true }];

    return bubble('GET', '/plan' + constraints(c) + '&limit=50&sort_field=Sort Order', null, function (e, j) {
      if (e) return responder(res, 502, { erro: e.message });
      const planos = (((j || {}).response || {}).results || []).map(function (p) {
        return {
          id: p._id, nome: p['Name'] || '', label: p['Storage Label'] || '',
          limite: Number(p['Storage Limit Bytes'] || 0),
          maxFicheiro: Number(p['Max File Size Bytes'] || 0),
          preco: Number(p['Price MZN'] || 0),
          utilizadores: Number(p['Max Users'] || 1),
          partilha: p['Allows Sharing'] === true,
          ordem: Number(p['Sort Order'] || 0)
        };
      });

      bubble('GET', '/storage pack' + constraints(c) + '&limit=50&sort_field=Sort Order', null, function (e2, j2) {
        const packs = e2 ? [] : (((j2 || {}).response || {}).results || []).map(function (p) {
          return {
            id: p._id, nome: p['Name'] || '', label: p['Label'] || '',
            bytes: Number(p['Bytes'] || 0),
            preco: Number(p['Price MZN'] || 0),
            precoAno: Number(p['Price Year MZN'] || 0),
            ordem: Number(p['Sort Order'] || 0)
          };
        });
        responder(res, 200, { ok: true, planos: planos, packs: packs, pagamento: Boolean(MOZ_WALLET) });
      });
    });
  }

  /* ---------- conta ---------- */
  if (rota === '/account' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        const c = [{ key: 'User', constraint_type: 'equals', value: u.id }];
        bubble('GET', '/payment' + constraints(c) + '&limit=10&sort_field=Created Date&descending=true',
          null, function (e3, j3) {
          const pagamentos = e3 ? [] : (((j3 || {}).response || {}).results || []).map(function (x) {
            return {
              id: x._id, metodo: x['Method'] || '', valor: Number(x['Amount MZN'] || 0),
              item: x['Item Name'] || '', estado: x['Status'] || '',
              transacao: x['Transaction'] || '', data: x['Created Date'] || ''
            };
          });

          responder(res, 200, {
            ok: true, nome: u.nome, email: u.email,
            usado: u.usado, base: u.base, extra: u.extra, limite: u.limite,
            expira: u.expira, dias: u.dias, expirado: u.expirado,
            excesso: u.excesso, bloqueio: porqueBloqueado(u),
            pagamento: Boolean(MOZ_WALLET), pagamentos: pagamentos
          });
        });
      });
    });
  }

  /* ---------- simular mudança de plano ---------- */
  if (rota === '/plan-check' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const planoId = String(p.plan_id || '').trim();
      if (!dono || !planoId) return responder(res, 400, { erro: 'Dados em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        bubble('GET', '/plan/' + encodeURIComponent(planoId), null, function (e3, jp) {
          if (e3) return responder(res, 404, { erro: 'Plano nao encontrado.' });
          const pl = (jp && jp.response) || jp;
          const novoBase = Number(pl['Storage Limit Bytes'] || 0);
          const falta = Math.max(0, u.usado - novoBase);

          if (!falta) {
            return responder(res, 200, {
              ok: true, cabe: true, falta: 0, plano_id: planoId,
              plano: pl['Name'] || '', label: pl['Storage Label'] || '',
              preco: Number(pl['Price MZN'] || 0), sugestao: null, packs: []
            });
          }

          const c = [{ key: 'Is Active', constraint_type: 'equals', value: true }];
          bubble('GET', '/storage pack' + constraints(c) + '&limit=50&sort_field=Sort Order', null, function (e4, j4) {
            const packs = e4 ? [] : (((j4 || {}).response || {}).results || []).map(function (x) {
              return {
                id: x._id, nome: x['Name'] || '', label: x['Label'] || '',
                bytes: Number(x['Bytes'] || 0),
                preco: Number(x['Price MZN'] || 0),
                precoAno: Number(x['Price Year MZN'] || 0),
                chega: Number(x['Bytes'] || 0) >= falta
              };
            });
            const suficientes = packs.filter(function (x) { return x.chega; });

            responder(res, 200, {
              ok: true, cabe: false, falta: falta, plano_id: planoId,
              plano: pl['Name'] || '', label: pl['Storage Label'] || '',
              preco: Number(pl['Price MZN'] || 0),
              sugestao: suficientes.length ? suficientes[0] : null,
              packs: packs
            });
          });
        });
      });
    });
  }

  /* ---------- PAGAR ---------- */
  if (rota === '/pay' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      if (!MOZ_WALLET) return responder(res, 500, { erro: 'Pagamentos nao configurados.' });

      const dono = String(p.owner || '').trim();
      const meio = String(p.metodo || '').toLowerCase().trim();
      const numero = limparNumero(p.numero);
      const tipo = String(p.tipo || '').toLowerCase().trim();
      const itemId = String(p.item_id || '').trim();
      const anual = p.anual === true;

      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });
      if (['mpesa', 'emola'].indexOf(meio) === -1) {
        return responder(res, 400, { erro: 'Escolhe M-Pesa ou e-Mola.' });
      }
      const erroNum = numeroValido(numero, meio);
      if (erroNum) return responder(res, 400, { erro: erroNum });
      if (['plan', 'pack'].indexOf(tipo) === -1) {
        return responder(res, 400, { erro: 'Tipo de compra invalido.' });
      }
      if (!itemId) return responder(res, 400, { erro: 'Item em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        const caminhoItem = tipo === 'plan'
          ? '/plan/' + encodeURIComponent(itemId)
          : '/storage pack/' + encodeURIComponent(itemId);

        bubble('GET', caminhoItem, null, function (e3, ji) {
          if (e3) return responder(res, 404, { erro: 'Item nao encontrado.' });
          const item = (ji && ji.response) || ji;

          if (item['Is Active'] === false) {
            return responder(res, 400, { erro: 'Este item ja nao esta disponivel.' });
          }

          const nome = item['Name'] || '';
          let valor, dias;

          if (tipo === 'plan') {
            valor = Number(item['Price MZN'] || 0);
            dias = 30;
          } else {
            valor = anual ? Number(item['Price Year MZN'] || 0) : Number(item['Price MZN'] || 0);
            dias = anual ? 365 : 30;
          }

          if (!valor || valor <= 0) {
            return responder(res, 400, {
              erro: 'Este item nao tem preco definido. Fala connosco para negociar.'
            });
          }

          cobrar(meio, numero, u.nome, valor, function (e4, r) {

            if (e4) {
              registarPagamento(u, {
                metodo: meio, numero: numero, valor: valor, tipo: tipo,
                nome: nome, itemId: itemId, estado: 'error',
                mensagem: e4.message, bruto: 'EXCEPCAO: ' + String(e4.message || '')
              });
              return responder(res, 502, { erro: e4.message });
            }

            if (!r.ok) {
              registarPagamento(u, {
                metodo: meio, numero: numero, valor: valor, tipo: tipo,
                nome: nome, itemId: itemId, estado: 'error',
                transacao: r.transacao,
                mensagem: r.mensagem || ('cod ' + r.cod),
                bruto: r.bruto
              });
              return responder(res, 402, {
                erro: r.mensagem || 'O pagamento nao foi aceite. Confirma o saldo e tenta outra vez.',
                cod: r.cod, transacao: r.transacao, detalhe: r.bruto
              });
            }

            const mudanca = {};

            if (tipo === 'plan') {
              mudanca['Plan'] = itemId;
              mudanca['Storage Limit Bytes'] = Number(item['Storage Limit Bytes'] || 0);
              mudanca['Max File Size Bytes'] = Number(item['Max File Size Bytes'] || 0);
              mudanca['Plan Started'] = new Date().toISOString();
              mudanca['Plan Expires'] = somaDias(u.expira, dias);
              mudanca['Is Active'] = true;
            } else {
              mudanca['Extra Storage Bytes'] = u.extra + Number(item['Bytes'] || 0);
              if (!u.expira || u.expirado) {
                mudanca['Plan Expires'] = somaDias(null, 30);
              }
            }

            bubble('PATCH', '/user/' + encodeURIComponent(u.id), mudanca, function (e5) {

              registarPagamento(u, {
                metodo: meio, numero: numero, valor: valor, tipo: tipo,
                nome: nome, itemId: itemId,
                estado: e5 ? 'error' : 'success',
                transacao: r.transacao,
                mensagem: e5 ? ('Pago mas nao aplicado: ' + e5.message) : (r.mensagem || 'Pago'),
                bruto: r.bruto
              });

              if (e5) {
                return responder(res, 500, {
                  erro: 'O pagamento foi feito mas a conta nao actualizou. Guarda a referencia '
                    + (r.transacao || '') + ' e fala connosco.',
                  transacao: r.transacao
                });
              }

              responder(res, 200, {
                ok: true, transacao: r.transacao, valor: valor, item: nome,
                expira: mudanca['Plan Expires'] || u.expira,
                limite: tipo === 'plan'
                  ? Number(item['Storage Limit Bytes'] || 0) + u.extra
                  : u.base + u.extra + Number(item['Bytes'] || 0)
              });
            });
          });
        });
      });
    });
  }

  /* ---------- INICIAR PAGAMENTO CARTÃO ---------- */
  if (rota === '/pay-card' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      if (!MOZ_WALLET) return responder(res, 500, { erro: 'Pagamentos nao configurados.' });

      const dono = String(p.owner || '').trim();
      const tipo = String(p.tipo || '').toLowerCase().trim();
      const itemId = String(p.item_id || '').trim();

      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });
      if (['plan', 'pack'].indexOf(tipo) === -1) {
        return responder(res, 400, { erro: 'Tipo de compra invalido.' });
      }
      if (!itemId) return responder(res, 400, { erro: 'Item em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        const caminhoItem = tipo === 'plan'
          ? '/plan/' + encodeURIComponent(itemId)
          : '/storage pack/' + encodeURIComponent(itemId);

        bubble('GET', caminhoItem, null, function (e3, ji) {
          if (e3) return responder(res, 404, { erro: 'Item nao encontrado.' });
          const item = (ji && ji.response) || ji;

          if (item['Is Active'] === false) {
            return responder(res, 400, { erro: 'Este item ja nao esta disponivel.' });
          }

          const nome = item['Name'] || '';
          const anual = p.anual === true;
          let valor;

          if (tipo === 'plan') {
            valor = Number(item['Price MZN'] || 0);
          } else {
            valor = anual
              ? Number(item['Price Year MZN'] || 0)
              : Number(item['Price MZN'] || 0);
          }

          if (!valor || valor <= 0) {
            return responder(res, 400, {
              erro: 'Este item nao tem preco definido. Fala connosco para negociar.'
            });
          }

          /* referencia unica para este pagamento */
          const referencia = 'BS-' + Date.now() + '-' + Math.floor(Math.random() * 100000);

          /* return_url com user e plano para a pagina /payment saber o que activar */
          const returnUrl = 'https://bag-security.com/payment?u='
            + encodeURIComponent(u.id)
            + '&p=' + encodeURIComponent(itemId)
            + '&t=' + encodeURIComponent(tipo)
            + '&ref=' + encodeURIComponent(referencia);

          /* guardar pendente no Bubble */
          bubble('POST', '/card_payment_pending', {
            'user_id': u.id,
            'plano': itemId,
            'valor': valor,
            'reference': referencia,
            'status': 'pending',
            'created_date': new Date().toISOString()
          }, function (e4) {
            if (e4) return responder(res, 502, { erro: 'Nao foi possivel registar o pagamento.' });

            /* chamar a MoPayment */
            const payload = JSON.stringify({
              valor: String(valor),
              nome_cliente: u.nome,
              carteira: MOZ_WALLET,
              return_url: returnUrl,
              nome_producto: 'Bag Security - ' + nome
            });

            const pedido = https.request({
              hostname: 'mozpayment.co.mz',
              path: '/api/1.1/wf/bankpayment',
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload)
              }
            }, function (r) {
              let texto = '';
              r.on('data', function (c) { texto += c; });
              r.on('end', function () {
                let j = null;
                try { j = JSON.parse(texto); } catch (e) { j = null; }

                if (!j) {
                  return responder(res, 502, {
                    erro: 'Resposta ilegivel da MoPayment.',
                    detalhe: 'HTTP ' + r.statusCode + ' | ' + String(texto).substring(0, 300)
                  });
                }

                /* a MoPayment devolve o URL de pagamento */
                const urlPagamento = (j.response && j.response.payment_url)
                  || j.payment_url || j.url || '';

                if (!urlPagamento) {
                  return responder(res, 502, {
                    erro: 'A MoPayment nao devolveu o link de pagamento.',
                    detalhe: JSON.stringify(j).substring(0, 300)
                  });
                }

                responder(res, 200, {
                  ok: true,
                  url: urlPagamento,
                  referencia: referencia,
                  valor: valor,
                  item: nome
                });
              });
            });

            pedido.setTimeout(30000, function () {
              pedido.destroy(new Error('MoPayment demorou demasiado.'));
            });
            pedido.on('error', function (e) {
              responder(res, 502, { erro: e.message });
            });
            pedido.write(payload);
            pedido.end();
          });
        });
      });
    });
  }

  /* ---------- WEBHOOK CARTÃO (MoPayment → proxy → Bubble) ---------- */
  if (rota === '/webhook-card' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });

      /* verificar token secreto no cabeçalho */
      const tokenRecebido = String(req.headers['x-webhook-secret'] || '').trim();
      if (!WEBHOOK_SECRET || tokenRecebido !== WEBHOOK_SECRET) {
        return responder(res, 401, { erro: 'Nao autorizado.' });
      }

      const referencia = String(p.reference || p.payment_id || '').trim();
      const status = String(p.status || '').toUpperCase().trim();

      if (!referencia) return responder(res, 400, { erro: 'Referencia em falta.' });

      /* procurar o registo pendente pelo campo reference */
      const c = [{ key: 'reference', constraint_type: 'equals', value: referencia }];
      bubble('GET', '/card_payment_pending' + constraints(c) + '&limit=1', null, function (e2, j2) {
        if (e2) return responder(res, 502, { erro: 'Erro ao procurar pagamento.' });

        const lista = (((j2 || {}).response || {}).results || []);
        if (!lista.length) return responder(res, 404, { erro: 'Pagamento nao encontrado.' });

        const pendente = lista[0];

        /* actualizar status no registo pendente */
        bubble('PATCH', '/card_payment_pending/' + encodeURIComponent(pendente._id), {
          'status': status === 'PAID' ? 'paid' : (status === 'FAILED' ? 'failed' : 'expired')
        }, function () {});

        /* só activar o plano se o pagamento foi bem sucedido */
        if (status !== 'PAID') {
          return responder(res, 200, { ok: true, ignorado: true, status: status });
        }

        const userId = String(pendente['user_id'] || '').trim();
        const planoId = String(pendente['plano'] || '').trim();
        const valor = Number(pendente['valor'] || 0);

        if (!userId || !planoId) {
          return responder(res, 400, { erro: 'Dados do pendente incompletos.' });
        }

        carregarUtilizador(userId, function (e3, u) {
          if (e3) return responder(res, 502, { erro: 'Utilizador nao encontrado.' });

          /* tentar carregar como plano primeiro */
          bubble('GET', '/plan/' + encodeURIComponent(planoId), null, function (e4, jp) {
            const ehPlano = !e4 && jp && ((jp.response || jp)['Name']);

            if (ehPlano) {
              const item = (jp.response || jp);
              const mudanca = {
                'Plan': planoId,
                'Storage Limit Bytes': Number(item['Storage Limit Bytes'] || 0),
                'Max File Size Bytes': Number(item['Max File Size Bytes'] || 0),
                'Plan Started': new Date().toISOString(),
                'Plan Expires': somaDias(u.expira, 30),
                'Is Active': true
              };

              bubble('PATCH', '/user/' + encodeURIComponent(u.id), mudanca, function (e5) {
                registarPagamento(u, {
                  metodo: 'card',
                  numero: '',
                  valor: valor,
                  tipo: 'plan',
                  nome: item['Name'] || '',
                  itemId: planoId,
                  estado: e5 ? 'error' : 'success',
                  transacao: String(p.transaction_id || p.payment_id || ''),
                  mensagem: e5 ? ('Pago mas nao aplicado: ' + e5.message) : 'Pago via cartao',
                  bruto: JSON.stringify(p).substring(0, 900)
                });

                responder(res, 200, { ok: true, activado: !e5, tipo: 'plan' });
              });

            } else {
              /* tentar como pack de storage */
              bubble('GET', '/storage pack/' + encodeURIComponent(planoId), null, function (e6, jk) {
                if (e6) return responder(res, 404, { erro: 'Item nao encontrado.' });
                const item = (jk.response || jk);

                const mudanca = {
                  'Extra Storage Bytes': u.extra + Number(item['Bytes'] || 0)
                };
                if (!u.expira || u.expirado) {
                  mudanca['Plan Expires'] = somaDias(null, 30);
                }

                bubble('PATCH', '/user/' + encodeURIComponent(u.id), mudanca, function (e7) {
                  registarPagamento(u, {
                    metodo: 'card',
                    numero: '',
                    valor: valor,
                    tipo: 'pack',
                    nome: item['Name'] || '',
                    itemId: planoId,
                    estado: e7 ? 'error' : 'success',
                    transacao: String(p.transaction_id || p.payment_id || ''),
                    mensagem: e7 ? ('Pago mas nao aplicado: ' + e7.message) : 'Pago via cartao',
                    bruto: JSON.stringify(p).substring(0, 900)
                  });

                  responder(res, 200, { ok: true, activado: !e7, tipo: 'pack' });
                });
              });
            }
          });
        });
      });
    });
  }

  /* ================= ENVIAR A OUTRO UTILIZADOR ================= */

  /* verifica antes de enviar: existe? tem espaco? */
  if (rota === '/send-check' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const email = String(p.email || '').trim();
      const id = String(p.id || '').trim();
      if (!dono || !email || !id) return responder(res, 400, { erro: 'Dados em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        if (String(email).toLowerCase() === String(u.email).toLowerCase()) {
          return responder(res, 400, { erro: 'Esse e o teu proprio email.' });
        }

        bubble('GET', '/stored file/' + encodeURIComponent(id), null, function (e3, jf) {
          if (e3) return responder(res, 404, { erro: 'Ficheiro nao encontrado.' });
          const f = (jf && jf.response) || jf;
          if (String(f['Owner']) !== String(u.id)) {
            return responder(res, 403, { erro: 'Este ficheiro nao e teu.' });
          }
          if (f['Is Deleted'] === true) {
            return responder(res, 400, { erro: 'Este ficheiro esta na lixeira.' });
          }
          if (f['Status'] === 'Processing') {
            return responder(res, 400, { erro: 'Espera que o video acabe de processar.' });
          }

          procurarPorEmail(email, function (e4, d) {
            if (e4) return responder(res, 502, { erro: e4.message });
            if (!d) {
              return responder(res, 404, {
                erro: 'Nao existe conta com esse email.', sem_conta: true
              });
            }

            const destino = moldarUtilizador(d);
            const tamanho = Number(f['Size Bytes'] || 0);
            const ext = String(f['Extension'] || '').toLowerCase();

            const bloqueio = porqueBloqueado(destino);
            const cabe = destino.limite === 0 || tamanho <= destino.livre;

            responder(res, 200, {
              ok: true,
              existe: true,
              nome_destino: destino.nome,
              email_destino: destino.email,
              tamanho: tamanho,
              livre_destino: destino.livre,
              cabe: cabe,
              falta: cabe ? 0 : (tamanho - destino.livre),
              bloqueado: Boolean(bloqueio),
              motivo: bloqueio || '',
              duplica: precisaCopia(ext),
              ficheiro: f['Original Name'] || f['Name'] || ''
            });
          });
        });
      });
    });
  }

  /* envia mesmo */
  if (rota === '/send' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const email = String(p.email || '').trim();
      const id = String(p.id || '').trim();
      const recado = String(p.message || '').substring(0, 300);
      if (!dono || !email || !id) return responder(res, 400, { erro: 'Dados em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        bubble('GET', '/stored file/' + encodeURIComponent(id), null, function (e3, jf) {
          if (e3) return responder(res, 404, { erro: 'Ficheiro nao encontrado.' });
          const f = (jf && jf.response) || jf;
          if (String(f['Owner']) !== String(u.id)) {
            return responder(res, 403, { erro: 'Este ficheiro nao e teu.' });
          }
          if (f['Is Deleted'] === true) {
            return responder(res, 400, { erro: 'Este ficheiro esta na lixeira.' });
          }

          procurarPorEmail(email, function (e4, d) {
            if (e4) return responder(res, 502, { erro: e4.message });
            if (!d) return responder(res, 404, { erro: 'Nao existe conta com esse email.', sem_conta: true });

            const destino = moldarUtilizador(d);
            if (destino.id === u.id) {
              return responder(res, 400, { erro: 'Esse e o teu proprio email.' });
            }

            const bloqueio = porqueBloqueado(destino);
            if (bloqueio) {
              return responder(res, 403, {
                erro: 'Quem vai receber tem a conta inactiva e nao pode receber ficheiros agora.'
              });
            }

            const tamanho = Number(f['Size Bytes'] || 0);
            if (destino.limite > 0 && tamanho > destino.livre) {
              return responder(res, 403, {
                erro: 'Quem vai receber nao tem espaco. Faltam '
                  + (tamanho - destino.livre) + ' bytes.',
                sem_espaco: true, falta: tamanho - destino.livre
              });
            }

            const ext = String(f['Extension'] || '').toLowerCase();
            const noStream = f['Storage Type'] === 'Bunny Stream';
            const nomeOriginal = f['Original Name'] || f['Name'] || 'ficheiro';

            /* monta o registo da copia */
            function registarCopia(caminhoNovo, ligada) {
              const registo = {
                'Owner': destino.id,
                'Name': caminhoNovo ? caminhoNovo.split('/').pop() : (f['Name'] || ''),
                'Original Name': nomeOriginal,
                'Extension': ext,
                'MIME Type': f['MIME Type'] || '',
                'File Type': f['File Type'] || classificar(ext),
                'Storage Type': f['Storage Type'] || 'Bunny Storage',
                'Status': 'Ready',
                'Size Bytes': tamanho,
                'Bunny Path': caminhoNovo || (f['Bunny Path'] || ''),
                'CDN URL': f['CDN URL'] || '',
                'Is Deleted': false,
                'Is Shared': false,
                'Sent By': u.id,
                'Source File': f._id,
                'Shares Storage': ligada === true
              };

              if (noStream) {
                registo['Bunny Video ID'] = f['Bunny Video ID'] || '';
                registo['Playback URL'] = f['Playback URL'] || '';
                registo['Thumbnail URL'] = f['Thumbnail URL'] || '';
              }

              bubble('POST', '/stored file', registo, function (e5, jn) {
                if (e5) return responder(res, 502, { erro: e5.message });

                bubble('PATCH', '/user/' + encodeURIComponent(destino.id), {
                  'Storage Used Bytes': destino.usado + tamanho
                }, function () {

                  bubble('POST', '/transfer', {
                    'From User': u.id,
                    'To User': destino.id,
                    'File Name': nomeOriginal,
                    'Copy': jn.id || '',
                    'Message': recado,
                    'Seen': false
                  }, function () {
                    responder(res, 200, {
                      ok: true,
                      para: destino.nome,
                      ficheiro: nomeOriginal,
                      copiado: !ligada
                    });
                  });
                });
              });
            }

            /* vídeos do Stream e ficheiros não editáveis: aponta para o mesmo */
            if (noStream || !precisaCopia(ext)) {
              return registarCopia(f['Bunny Path'] || '', true);
            }

            /* editáveis: copia mesmo, para cada um ter o seu */
            const origem = f['Bunny Path'] || '';
            if (!origem) return responder(res, 400, { erro: 'Ficheiro sem caminho.' });

            const unico = Date.now() + '-' + Math.floor(Math.random() * 100000)
              + '-' + limpar(nomeOriginal);
            const caminhoNovo = limpar(destino.id) + '/' + unico;

            copiarNoBunny(origem, caminhoNovo, function (e6) {
              if (e6) return responder(res, 502, { erro: 'Nao foi possivel copiar: ' + e6.message });
              registarCopia(caminhoNovo, false);
            });
          });
        });
      });
    });
  }

  /* avisos de ficheiros recebidos */
  if (rota === '/inbox' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        const c = [{ key: 'To User', constraint_type: 'equals', value: u.id }];
        bubble('GET', '/transfer' + constraints(c) + '&limit=30&sort_field=Created Date&descending=true',
          null, function (e3, j) {
          if (e3) return responder(res, 502, { erro: e3.message });
          const lista = (((j || {}).response || {}).results || []);

          const porVer = lista.filter(function (t) { return t['Seen'] !== true; }).length;

          responder(res, 200, {
            ok: true, por_ver: porVer,
            envios: lista.map(function (t) {
              return {
                id: t._id,
                ficheiro: t['File Name'] || '',
                copia: t['Copy'] || '',
                recado: t['Message'] || '',
                visto: t['Seen'] === true,
                data: t['Created Date'] || ''
              };
            })
          });
        });
      });
    });
  }

  /* marcar avisos como vistos */
  if (rota === '/inbox-seen' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        const c = [
          { key: 'To User', constraint_type: 'equals', value: u.id },
          { key: 'Seen', constraint_type: 'equals', value: false }
        ];
        bubble('GET', '/transfer' + constraints(c) + '&limit=100', null, function (e3, j) {
          const lista = e3 ? [] : (((j || {}).response || {}).results || []);
          let feitos = 0;
          if (!lista.length) return responder(res, 200, { ok: true, marcados: 0 });

          lista.forEach(function (t) {
            bubble('PATCH', '/transfer/' + encodeURIComponent(t._id), { 'Seen': true }, function () {
              feitos++;
              if (feitos === lista.length) responder(res, 200, { ok: true, marcados: feitos });
            });
          });
        });
      });
    });
  }

  /* ---------- estatisticas ---------- */
  if (rota === '/stats' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        const cs = [
          { key: 'Owner', constraint_type: 'equals', value: u.id },
          { key: 'Is Deleted', constraint_type: 'equals', value: false }
        ];

        buscarTudo('/stored file', cs, '&sort_field=Created Date&descending=true', function (e3, todos) {
          if (e3) return responder(res, 502, { erro: e3.message });

          const contagem = {}, bytes = {};
          todos.forEach(function (f) {
            const t = f['File Type'] || 'Other';
            contagem[t] = (contagem[t] || 0) + 1;
            bytes[t] = (bytes[t] || 0) + Number(f['Size Bytes'] || 0);
          });

          responder(res, 200, {
            ok: true, total: todos.length, contagem: contagem, bytes: bytes,
            partilhados: todos.filter(function (f) { return f['Is Shared'] === true; }).length,
            recebidos: todos.filter(function (f) { return Boolean(f['Sent By']); }).length,
            recentes: todos.slice(0, 8).map(mapear),
            usado: u.usado, limite: u.limite, base: u.base, extra: u.extra,
            dias: u.dias, expirado: u.expirado, excesso: u.excesso,
            bloqueio: porqueBloqueado(u)
          });
        });
      });
    });
  }

  /* ================= ONLYOFFICE ================= */

  if (rota === '/office' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      if (!OO_URL || !OO_SECRET) return responder(res, 500, { erro: 'Editor nao configurado.' });

      const dono = String(p.owner || '').trim();
      const id = String(p.id || '').trim();
      if (!dono || !id) return responder(res, 400, { erro: 'Dados em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        bubble('GET', '/stored file/' + encodeURIComponent(id), null, function (e3, jf) {
          if (e3) return responder(res, 404, { erro: 'Ficheiro nao encontrado.' });
          const f = (jf && jf.response) || jf;
          if (String(f['Owner']) !== String(u.id)) {
            return responder(res, 403, { erro: 'Este ficheiro nao e teu.' });
          }

          const ext = String(f['Extension'] || '').toLowerCase();
          const tipoDoc = ooTipo(ext);
          if (!tipoDoc) return responder(res, 400, { erro: 'Este formato nao abre no editor.' });

          const caminho = f['Bunny Path'] || '';
          const bloqueio = porqueBloqueado(u);
          const ligado = f['Shares Storage'] === true;
          const podeEditar = p.edit === true && ooEditavel(ext) && !bloqueio && !ligado;

          const chave = crypto.createHash('md5')
            .update(id + '|' + (f['Modified Date'] || f['Created Date'] || ''))
            .digest('hex').substring(0, 20);

          const expiraCb = Math.floor(Date.now() / 1000) + 86400;
          const tokenCb = expiraCb + '.' + assinar(id + '|' + caminho + '|' + expiraCb);
          const base = SELF_URL || ('https://' + (req.headers.host || ''));

          const config = {
            document: {
              fileType: ext, key: chave,
              title: f['Original Name'] || f['Name'] || 'documento',
              url: urlAssinado(caminho, 86400),
              permissions: {
                edit: podeEditar, download: true, print: true,
                comment: podeEditar, fillForms: podeEditar
              }
            },
            documentType: tipoDoc,
            type: 'desktop',
            editorConfig: {
              mode: podeEditar ? 'edit' : 'view',
              lang: 'pt',
              user: { id: u.id, name: u.nome },
              customization: { autosave: true, forcesave: true, compactHeader: false }
            }
          };

          if (podeEditar) {
            config.editorConfig.callbackUrl = base + '/office-save'
              + '?id=' + encodeURIComponent(id) + '&t=' + encodeURIComponent(tokenCb);
          }

          config.token = jwtAssinar(config);

          responder(res, 200, {
            ok: true, server: OO_URL, config: config, editar: podeEditar,
            nome: f['Original Name'] || f['Name'] || '',
            bloqueio: (p.edit === true && bloqueio) ? bloqueio : null
          });
        });
      });
    });
  }

  if (rota === '/office-save' && metodo === 'POST') {
    const id = url.searchParams.get('id') || '';
    const t = url.searchParams.get('t') || '';

    return lerJson(req, function (err, corpo) {
      if (err) { res.writeHead(200, {'Content-Type':'application/json'}); return res.end('{"error":1}'); }

      function fim(codigo) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: codigo }));
      }

      const estado = Number(corpo.status || 0);
      if (estado !== 2 && estado !== 6) return fim(0);

      const partes = String(t).split('.');
      if (partes.length !== 2) return fim(1);
      const expira = Number(partes[0]);
      if (!expira || Math.floor(Date.now() / 1000) > expira) return fim(1);

      const jwtToken = corpo.token || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      if (OO_SECRET && jwtToken && !jwtVerificar(jwtToken)) return fim(1);

      bubble('GET', '/stored file/' + encodeURIComponent(id), null, function (e2, jf) {
        if (e2) return fim(1);
        const f = (jf && jf.response) || jf;
        const caminho = f['Bunny Path'] || '';
        if (!caminho) return fim(1);
        if (f['Shares Storage'] === true) return fim(1);
        if (!iguais(partes[1], assinar(id + '|' + caminho + '|' + expira))) return fim(1);

        const origem = corpo.url;
        if (!origem) return fim(1);

        guardarDeUrl(origem, caminho, f['MIME Type'] || '', function (e3) {
          if (e3) return fim(1);
          bubble('PATCH', '/stored file/' + encodeURIComponent(id), { 'Status': 'Ready' }, function () { fim(0); });
        });
      });
    });
  }

  if (rota === '/office-new' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const tipo = String(p.tipo || 'docx').toLowerCase();
      const nome = limparNome(p.name) || 'Documento sem titulo';
      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });
      if (['docx','xlsx','pptx'].indexOf(tipo) === -1) {
        return responder(res, 400, { erro: 'Tipo invalido.' });
      }

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        const bloqueio = porqueBloqueado(u);
        if (bloqueio) return responder(res, 403, { erro: bloqueio, bloqueado: true });
        if (u.limite > 0 && u.usado >= u.limite) {
          return responder(res, 403, { erro: 'Sem espaco disponivel.', excesso: true });
        }

        const nomeFicheiro = nome.replace(/\.(docx|xlsx|pptx)$/i, '') + '.' + tipo;

        let conteudo;
        try { conteudo = ficheiroVazio(tipo); }
        catch (ex) { return responder(res, 500, { erro: 'Nao foi possivel gerar o documento.' }); }

        const mimes = {
          docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
          xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
        };

        const unico = Date.now() + '-' + Math.floor(Math.random() * 100000) + '-' + limpar(nomeFicheiro);
        const caminho = limpar(u.id) + '/' + unico;

        guardarBuffer(conteudo, caminho, mimes[tipo], function (e3) {
          if (e3) return responder(res, 502, { erro: 'Nao foi possivel criar: ' + e3.message });

          const registo = {
            'Owner': u.id, 'Name': unico, 'Original Name': nomeFicheiro,
            'Extension': tipo, 'MIME Type': mimes[tipo],
            'File Type': classificar(tipo),
            'Storage Type': 'Bunny Storage', 'Status': 'Ready',
            'Size Bytes': conteudo.length, 'Bunny Path': caminho,
            'CDN URL': CDN ? 'https://' + CDN + '/' + encodeURI(caminho) : '',
            'Is Deleted': false, 'Is Shared': false, 'Shares Storage': false
          };
          if (p.folder_id) registo['Folder'] = String(p.folder_id);

          bubble('POST', '/stored file', registo, function (e4, j) {
            if (e4) return responder(res, 502, { erro: e4.message });
            bubble('PATCH', '/user/' + encodeURIComponent(u.id), {
              'Storage Used Bytes': u.usado + conteudo.length
            }, function () {
              responder(res, 200, { ok: true, id: j.id || '', nome: nomeFicheiro });
            });
          });
        });
      });
    });
  }

  /* ================= UPLOAD ================= */

  if (rota === '/token' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });

      const nomeBruto = String(p.name || '').trim();
      const nome = limpar(nomeBruto);
      const tamanho = parseInt(String(p.size || '0').replace(/[^0-9]/g, ''), 10);
      const pasta = limpar(p.folder);
      const pedidoDono = String(p.owner || '').trim();

      if (!nome) return responder(res, 400, { erro: 'Nome em falta.' });
      if (!tamanho || tamanho <= 0) return responder(res, 400, { erro: 'Tamanho invalido.' });
      if (!pedidoDono) return responder(res, 403, { erro: 'Utilizador em falta.' });

      const ext = (nomeBruto.split('.').pop() || '').toLowerCase();
      const video = eVideo(ext) && Boolean(STREAM_LIB && STREAM_KEY);

      carregarUtilizador(pedidoDono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        const bloqueio = porqueBloqueado(u);
        if (bloqueio) return responder(res, 403, { erro: bloqueio, bloqueado: true });

        if (u.maxFicheiro > 0 && tamanho > u.maxFicheiro) {
          return responder(res, 403, { erro: 'Ficheiro acima do limite do plano.' });
        }
        if (u.limite > 0 && tamanho > u.livre) {
          return responder(res, 403, {
            erro: 'Sem espaco suficiente.',
            excesso: true, falta: Math.max(0, tamanho - u.livre)
          });
        }

        if (video) {
          return stream('POST', '/videos', { title: limparNome(nomeBruto) }, function (e3, v) {
            if (e3) return responder(res, 502, { erro: e3.message });
            const vid = v && v.guid;
            if (!vid) return responder(res, 502, { erro: 'O Stream nao devolveu o video.' });
            const expira = Math.floor(Date.now() / 1000) + 7200;
            responder(res, 200, {
              ok: true, modo: 'stream', video_id: vid, library: STREAM_LIB,
              expires: expira, signature: assinaturaTus(vid, expira),
              endpoint: 'https://video.bunnycdn.com/tusupload'
            });
          });
        }

        const dono = limpar(u.id);
        const unico = Date.now() + '-' + Math.floor(Math.random() * 100000) + '-' + nome;
        const caminho = dono + (pasta ? '/' + pasta : '') + '/' + unico;
        const expira = Math.floor(Date.now() / 1000) + 7200;
        const token = expira + '.' + tamanho + '.' + assinar(caminho + '|' + expira + '|' + tamanho);

        responder(res, 200, { ok: true, modo: 'storage', token: token, path: caminho, expires: expira });
      });
    });
  }

  if (rota === '/upload' && (metodo === 'POST' || metodo === 'PUT')) {
    if (!ZONE || !PASS || !HOST || !SEGREDO) {
      return responder(res, 500, { erro: 'Configuracao incompleta.' });
    }

    const token = req.headers['x-bsu-token'] || '';
    const caminho = limpar(req.headers['x-bsu-path'] || '');
    const tipo = req.headers['x-bsu-type'] || 'application/octet-stream';

    if (!token) return responder(res, 403, { erro: 'Token em falta.' });
    if (!caminho) return responder(res, 400, { erro: 'Caminho em falta.' });

    const partes = String(token).split('.');
    if (partes.length !== 3) return responder(res, 403, { erro: 'Token mal formado.' });

    const expira = Number(partes[0]);
    const tamanho = Number(partes[1]);
    if (!expira || !tamanho) return responder(res, 403, { erro: 'Token mal formado.' });
    if (Math.floor(Date.now() / 1000) > expira) return responder(res, 403, { erro: 'Token expirado.' });
    if (!iguais(partes[2], assinar(caminho + '|' + expira + '|' + tamanho))) {
      return responder(res, 403, { erro: 'Token invalido.' });
    }

    const declarado = Number(req.headers['content-length'] || 0);
    if (declarado > 0 && declarado > tamanho + 4096) {
      return responder(res, 403, { erro: 'Tamanho nao autorizado.' });
    }

    const opcoes = {
      hostname: HOST, path: '/' + ZONE + '/' + encodeURI(caminho),
      method: 'PUT', headers: { 'AccessKey': PASS, 'Content-Type': tipo }
    };
    if (req.headers['content-length']) opcoes.headers['Content-Length'] = req.headers['content-length'];
    else opcoes.headers['Transfer-Encoding'] = 'chunked';

    const pedido = https.request(opcoes, function (bunny) {
      let corpo = '';
      bunny.on('data', function (c) { corpo += c; });
      bunny.on('end', function () {
        if (bunny.statusCode !== 201 && bunny.statusCode !== 200) {
          return responder(res, 502, { erro: 'Bunny respondeu ' + bunny.statusCode });
        }
        responder(res, 200, { ok: true, caminho: caminho });
      });
    });
    pedido.on('error', function (e) {
      responder(res, 502, { erro: 'Falha ao contactar o Bunny.', detalhe: String(e.message) });
    });
    req.on('error', function () { pedido.destroy(); });
    req.pipe(pedido);
    return;
  }

  if (rota === '/create' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });

      const dono = String(p.owner || '').trim();
      const tamanho = parseInt(String(p.size || '0').replace(/[^0-9]/g, ''), 10);
      const modoStream = String(p.mode || '') === 'stream';
      const videoId = String(p.video_id || '').trim();
      const caminho = modoStream ? '' : limpar(p.path);

      if (!dono || !tamanho) return responder(res, 400, { erro: 'Dados em falta.' });
      if (modoStream && !videoId) return responder(res, 400, { erro: 'Video em falta.' });
      if (!modoStream && !caminho) return responder(res, 400, { erro: 'Caminho em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });
        if (!modoStream && caminho.indexOf(limpar(u.id) + '/') !== 0) {
          return responder(res, 403, { erro: 'Caminho nao pertence ao utilizador.' });
        }

        const ext = String(p.extension || '').toLowerCase().replace(/[^a-z0-9]/g, '');
        const registo = {
          'Owner': u.id,
          'Name': modoStream ? videoId : caminho.split('/').pop(),
          'Original Name': limparNome(p.original_name),
          'Extension': ext,
          'MIME Type': String(p.mime || '').substring(0, 120),
          'File Type': classificar(ext),
          'Storage Type': modoStream ? 'Bunny Stream' : 'Bunny Storage',
          'Status': modoStream ? 'Processing' : 'Ready',
          'Size Bytes': tamanho,
          'Bunny Path': caminho,
          'Is Deleted': false, 'Is Shared': false, 'Shares Storage': false
        };

        if (modoStream) {
          registo['Bunny Video ID'] = videoId;
          registo['Playback URL'] = STREAM_CDN ? 'https://' + STREAM_CDN + '/' + videoId + '/playlist.m3u8' : '';
          registo['Thumbnail URL'] = STREAM_CDN ? 'https://' + STREAM_CDN + '/' + videoId + '/thumbnail.jpg' : '';
          registo['CDN URL'] = 'https://iframe.mediadelivery.net/embed/' + STREAM_LIB + '/' + videoId;
        } else {
          registo['CDN URL'] = CDN ? 'https://' + CDN + '/' + encodeURI(caminho) : '';
        }

        if (p.folder_id) registo['Folder'] = String(p.folder_id);

        bubble('POST', '/stored file', registo, function (e3, j) {
          if (e3) return responder(res, 502, { erro: e3.message });
          bubble('PATCH', '/user/' + encodeURIComponent(u.id), {
            'Storage Used Bytes': u.usado + tamanho
          }, function () {
            responder(res, 200, { ok: true, id: j.id || '', usado: u.usado + tamanho, limite: u.limite });
          });
        });
      });
    });
  }

  if (rota === '/video-status' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const id = String(p.id || '').trim();
      if (!dono || !id) return responder(res, 400, { erro: 'Dados em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });
        bubble('GET', '/stored file/' + encodeURIComponent(id), null, function (e3, jf) {
          if (e3) return responder(res, 404, { erro: 'Ficheiro nao encontrado.' });
          const f = (jf && jf.response) || jf;
          if (String(f['Owner']) !== String(u.id)) {
            return responder(res, 403, { erro: 'Este ficheiro nao e teu.' });
          }
          const vid = f['Bunny Video ID'];
          if (!vid) return responder(res, 400, { erro: 'Nao e um video do Stream.' });

          stream('GET', '/videos/' + encodeURIComponent(vid), null, function (e4, v) {
            if (e4) return responder(res, 502, { erro: e4.message });
            const st = Number(v.status || 0);
            const pronto = st >= 3 && st <= 4;
            const falhou = st === 5 || st === 6;
            const novo = pronto ? 'Ready' : (falhou ? 'Error' : 'Processing');

            if (novo !== f['Status']) {
              bubble('PATCH', '/stored file/' + encodeURIComponent(id), { 'Status': novo }, function () {});
            }
            responder(res, 200, {
              ok: true, estado: novo, progresso: Number(v.encodeProgress || 0),
              duracao: Number(v.length || 0)
            });
          });
        });
      });
    });
  }

  /* ================= GESTÃO ================= */

  if (rota === '/files' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        const lixo = p.trash === true;
        const porTipo = !lixo && p.type;
        const soPartilhados = !lixo && p.shared === true;
        const soRecebidos = !lixo && p.received === true;
        const recentes = !lixo && p.recent === true;
        const global = porTipo || soPartilhados || soRecebidos || recentes;

        const cf = [
          { key: 'Owner', constraint_type: 'equals', value: u.id },
          { key: 'Is Deleted', constraint_type: 'equals', value: lixo }
        ];
        if (porTipo) cf.push({ key: 'File Type', constraint_type: 'equals', value: String(p.type) });
        if (soPartilhados) cf.push({ key: 'Is Shared', constraint_type: 'equals', value: true });
        if (soRecebidos) cf.push({ key: 'Sent By', constraint_type: 'is_not_empty' });

        if (!global && !lixo) {
          if (p.folder_id) cf.push({ key: 'Folder', constraint_type: 'equals', value: String(p.folder_id) });
          else cf.push({ key: 'Folder', constraint_type: 'is_empty' });
        }

        const estadoConta = {
          usado: u.usado, limite: u.limite, base: u.base, extra: u.extra,
          dias: u.dias, expirado: u.expirado, excesso: u.excesso,
          bloqueio: porqueBloqueado(u)
        };

        bubble('GET', '/stored file' + constraints(cf) + '&limit=100&sort_field=Created Date&descending=true',
          null, function (e3, jf) {
          if (e3) return responder(res, 502, { erro: e3.message });
          const ficheiros = (((jf || {}).response || {}).results || []).map(mapear);

          if (global || lixo) {
            return responder(res, 200, Object.assign({
              ok: true, pastas: [], ficheiros: ficheiros
            }, estadoConta));
          }

          const cp = [
            { key: 'Owner', constraint_type: 'equals', value: u.id },
            { key: 'Is Deleted', constraint_type: 'equals', value: false }
          ];
          if (p.folder_id) cp.push({ key: 'Parent Folder', constraint_type: 'equals', value: String(p.folder_id) });
          else cp.push({ key: 'Parent Folder', constraint_type: 'is_empty' });

          bubble('GET', '/folder' + constraints(cp) + '&limit=100&sort_field=Name', null, function (e4, jp) {
            const pastas = e4 ? [] : (((jp || {}).response || {}).results || []).map(function (d) {
              return { id: d._id, nome: d['Name'] || '', caminho: d['Path'] || '' };
            });
            responder(res, 200, Object.assign({
              ok: true, pastas: pastas, ficheiros: ficheiros
            }, estadoConta));
          });
        });
      });
    });
  }

  if (rota === '/delete' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const id = String(p.id || '').trim();
      if (!dono || !id) return responder(res, 400, { erro: 'Dados em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        if (p.folder === true) {
          return bubble('GET', '/folder/' + encodeURIComponent(id), null, function (e3, jp) {
            if (e3) return responder(res, 404, { erro: 'Pasta nao encontrada.' });
            const d = (jp && jp.response) || jp;
            if (String(d['Owner']) !== String(u.id)) {
              return responder(res, 403, { erro: 'Esta pasta nao e tua.' });
            }
            bubble('PATCH', '/folder/' + encodeURIComponent(id), {
              'Is Deleted': true, 'Deleted Date': new Date().toISOString()
            }, function (e4) {
              if (e4) return responder(res, 502, { erro: e4.message });
              responder(res, 200, { ok: true });
            });
          });
        }

        bubble('GET', '/stored file/' + encodeURIComponent(id), null, function (e3, jf) {
          if (e3) return responder(res, 404, { erro: 'Ficheiro nao encontrado.' });
          const f = (jf && jf.response) || jf;
          if (String(f['Owner']) !== String(u.id)) {
            return responder(res, 403, { erro: 'Este ficheiro nao e teu.' });
          }

          if (p.permanent !== true) {
            return bubble('PATCH', '/stored file/' + encodeURIComponent(id), {
              'Is Deleted': true, 'Deleted Date': new Date().toISOString()
            }, function (e4) {
              if (e4) return responder(res, 502, { erro: e4.message });
              responder(res, 200, { ok: true, lixeira: true });
            });
          }

          function terminar() {
            bubble('DELETE', '/stored file/' + encodeURIComponent(id), null, function (e5) {
              if (e5) return responder(res, 502, { erro: e5.message });
              const novo = Math.max(0, u.usado - Number(f['Size Bytes'] || 0));
              bubble('PATCH', '/user/' + encodeURIComponent(u.id), { 'Storage Used Bytes': novo }, function () {
                responder(res, 200, { ok: true, definitivo: true, usado: novo, limite: u.limite });
              });
            });
          }

          if (f['Shares Storage'] === true) return terminar();

          const caminhoOriginal = f['Bunny Path'] || '';
          const vid = f['Bunny Video ID'];

          const cLigadas = [
            { key: 'Source File', constraint_type: 'equals', value: f._id },
            { key: 'Shares Storage', constraint_type: 'equals', value: true },
            { key: 'Is Deleted', constraint_type: 'equals', value: false }
          ];

          bubble('GET', '/stored file' + constraints(cLigadas) + '&limit=1', null, function (e6, jl) {
            const temLigadas = !e6 && (((jl || {}).response || {}).results || []).length > 0;

            if (temLigadas) return terminar();

            if (vid) return stream('DELETE', '/videos/' + encodeURIComponent(vid), null, function () { terminar(); });
            apagarNoBunny(caminhoOriginal, function () { terminar(); });
          });
        });
      });
    });
  }

  if (rota === '/restore' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const id = String(p.id || '').trim();
      if (!dono || !id) return responder(res, 400, { erro: 'Dados em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });
        const tipo = p.folder === true ? '/folder/' : '/stored file/';
        bubble('GET', tipo + encodeURIComponent(id), null, function (e3, j) {
          if (e3) return responder(res, 404, { erro: 'Nao encontrado.' });
          const d = (j && j.response) || j;
          if (String(d['Owner']) !== String(u.id)) return responder(res, 403, { erro: 'Nao e teu.' });
          bubble('PATCH', tipo + encodeURIComponent(id), { 'Is Deleted': false }, function (e4) {
            if (e4) return responder(res, 502, { erro: e4.message });
            responder(res, 200, { ok: true });
          });
        });
      });
    });
  }

  if (rota === '/rename' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const id = String(p.id || '').trim();
      const nome = limparNome(p.name);
      const ePasta = p.folder === true;
      if (!dono || !id || !nome) return responder(res, 400, { erro: 'Dados em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });
        const tipo = ePasta ? '/folder/' : '/stored file/';
        bubble('GET', tipo + encodeURIComponent(id), null, function (e3, j) {
          if (e3) return responder(res, 404, { erro: 'Nao encontrado.' });
          const d = (j && j.response) || j;
          if (String(d['Owner']) !== String(u.id)) return responder(res, 403, { erro: 'Nao e teu.' });

          const campo = ePasta ? { 'Name': nome } : { 'Original Name': nome };
          bubble('PATCH', tipo + encodeURIComponent(id), campo, function (e4) {
            if (e4) return responder(res, 502, { erro: e4.message });
            const vid = !ePasta && d['Bunny Video ID'] && d['Shares Storage'] !== true;
            if (vid) stream('POST', '/videos/' + encodeURIComponent(vid), { title: nome }, function () {});
            responder(res, 200, { ok: true, nome: nome });
          });
        });
      });
    });
  }

  if (rota === '/move' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const id = String(p.id || '').trim();
      if (!dono || !id) return responder(res, 400, { erro: 'Dados em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });
        bubble('GET', '/stored file/' + encodeURIComponent(id), null, function (e3, jf) {
          if (e3) return responder(res, 404, { erro: 'Ficheiro nao encontrado.' });
          const f = (jf && jf.response) || jf;
          if (String(f['Owner']) !== String(u.id)) {
            return responder(res, 403, { erro: 'Este ficheiro nao e teu.' });
          }
          bubble('PATCH', '/stored file/' + encodeURIComponent(id), {
            'Folder': p.folder_id ? String(p.folder_id) : null
          }, function (e4) {
            if (e4) return responder(res, 502, { erro: e4.message });
            responder(res, 200, { ok: true });
          });
        });
      });
    });
  }

  if (rota === '/folder' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const nome = limparNome(p.name);
      if (!dono || !nome) return responder(res, 400, { erro: 'Dados em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        function criar(caminhoPai) {
          const registo = {
            'Name': nome, 'Owner': u.id,
            'Path': (caminhoPai ? caminhoPai + '/' : '') + limpar(nome),
            'Is Deleted': false
          };
          if (p.parent_id) registo['Parent Folder'] = String(p.parent_id);
          bubble('POST', '/folder', registo, function (e4, j) {
            if (e4) return responder(res, 502, { erro: e4.message });
            responder(res, 200, { ok: true, id: j.id || '', nome: nome, caminho: registo['Path'] });
          });
        }

        if (!p.parent_id) return criar('');
        bubble('GET', '/folder/' + encodeURIComponent(p.parent_id), null, function (e5, jp) {
          const d = e5 ? null : ((jp && jp.response) || jp);
          criar(d ? (d['Path'] || '') : '');
        });
      });
    });
  }

  if (rota === '/share' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const id = String(p.id || '').trim();
      if (!dono || !id) return responder(res, 400, { erro: 'Dados em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });
        bubble('GET', '/stored file/' + encodeURIComponent(id), null, function (e3, jf) {
          if (e3) return responder(res, 404, { erro: 'Ficheiro nao encontrado.' });
          const f = (jf && jf.response) || jf;
          if (String(f['Owner']) !== String(u.id)) {
            return responder(res, 403, { erro: 'Este ficheiro nao e teu.' });
          }

          if (p.revoke === true) {
            return bubble('PATCH', '/stored file/' + encodeURIComponent(id), {
              'Is Shared': false, 'Share Token': ''
            }, function () { responder(res, 200, { ok: true, revogado: true }); });
          }

          const chave = crypto.randomBytes(16).toString('hex');
          const dias = Math.min(365, Math.max(1, parseInt(p.days || '7', 10)));
          const mudanca = {
            'Is Shared': true, 'Share Token': chave,
            'Share Expires': new Date(Date.now() + dias * 86400000).toISOString(),
            'Share Downloads': 0
          };
          if (p.max_downloads) mudanca['Share Max Downloads'] = parseInt(p.max_downloads, 10) || 0;
          if (p.password) mudanca['Share Password'] = String(p.password).substring(0, 60);

          bubble('PATCH', '/stored file/' + encodeURIComponent(id), mudanca, function (e4) {
            if (e4) return responder(res, 502, { erro: e4.message });
            responder(res, 200, { ok: true, token: chave, expira: mudanca['Share Expires'] });
          });
        });
      });
    });
  }

  if (rota === '/shared' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const chave = String(p.token || '').trim();
      if (!chave) return responder(res, 400, { erro: 'Token em falta.' });

      const c = [
        { key: 'Share Token', constraint_type: 'equals', value: chave },
        { key: 'Is Shared', constraint_type: 'equals', value: true },
        { key: 'Is Deleted', constraint_type: 'equals', value: false }
      ];

      bubble('GET', '/stored file' + constraints(c) + '&limit=1', null, function (e2, j) {
        if (e2) return responder(res, 502, { erro: e2.message });
        const lista = (((j || {}).response || {}).results || []);
        if (!lista.length) return responder(res, 404, { erro: 'Link invalido.' });
        const f = lista[0];

        if (f['Share Expires'] && new Date(f['Share Expires']) < new Date()) {
          return responder(res, 410, { erro: 'Este link expirou.' });
        }
        const max = Number(f['Share Max Downloads'] || 0);
        const feitos = Number(f['Share Downloads'] || 0);
        if (max > 0 && feitos >= max) {
          return responder(res, 410, { erro: 'Limite de acessos atingido.' });
        }
        if (f['Share Password'] && String(p.password || '') !== f['Share Password']) {
          return responder(res, 401, { erro: 'Password incorreta.', precisa_password: true });
        }

        bubble('PATCH', '/stored file/' + encodeURIComponent(f._id), {
          'Share Downloads': feitos + 1
        }, function () {
          const m = mapear(f);
          responder(res, 200, {
            ok: true, nome: m.nome, tipo: m.tipo, ext: m.ext, tamanho: m.tamanho,
            url: m.url, player: m.player, stream: m.stream
          });
        });
      });
    });
  }

  if (rota === '/link' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const id = String(p.id || '').trim();
      if (!dono || !id) return responder(res, 400, { erro: 'Dados em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });
        bubble('GET', '/stored file/' + encodeURIComponent(id), null, function (e3, jf) {
          if (e3) return responder(res, 404, { erro: 'Ficheiro nao encontrado.' });
          const f = (jf && jf.response) || jf;
          if (String(f['Owner']) !== String(u.id)) {
            return responder(res, 403, { erro: 'Este ficheiro nao e teu.' });
          }
          const m = mapear(f);
          responder(res, 200, { ok: true, url: m.url, player: m.player });
        });
      });
    });
  }

  /* ================= CONTA E EMAIL ================= */

  if (rota === '/signup-code' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });

      const dono = String(p.owner || '').trim();
      const primeiro = p.welcome === true;
      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });

      if (!podePedir(dono)) {
        return responder(res, 429, {
          erro: 'Pediste codigos demasiadas vezes. Espera uma hora e tenta outra vez.'
        });
      }

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });
        if (!u.email) return responder(res, 400, { erro: 'Esta conta nao tem email.' });

        const codigo = gerarCodigo();
        const validade = new Date(Date.now() + 1800000).toISOString();

        bubble('PATCH', '/user/' + encodeURIComponent(u.id), {
          'Token': codigo,
          'Token Expires': validade,
          'Token Confirmado': false
        }, function (e3) {
          if (e3) return responder(res, 502, { erro: 'Nao foi possivel guardar o codigo.' });

          const m = emailCodigo(u.nome, codigo);
          enviarEmail(u.email, 'O teu codigo Bag Security: ' + codigo,
            m.html, m.texto, function (e4, r) {
            if (e4) {
              return responder(res, 502, {
                erro: 'A conta foi criada mas o email nao saiu. '
                  + 'Carrega em reenviar daqui a pouco.',
                detalhe: e4.message
              });
            }
            responder(res, 200, {
              ok: true, email: u.email, expira: validade, id: r.id, primeiro: primeiro
            });
          });
        });
      });
    });
  }

  if (rota === '/verify-code' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });

      const dono = String(p.owner || '').trim();
      const codigo = String(p.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });
      if (codigo.length !== 8) return responder(res, 400, { erro: 'Codigo incompleto.' });

      bubble('GET', '/user/' + encodeURIComponent(dono), null, function (e2, j) {
        if (e2) return responder(res, 403, { erro: 'Utilizador nao encontrado.' });
        const d = (j && j.response) || j;
        const u = moldarUtilizador(d);

        if (d['Token Confirmado'] === true) {
          return responder(res, 200, { ok: true, ja_confirmado: true });
        }

        const guardado = String(d['Token'] || '').toUpperCase();
        const expira = d['Token Expires'] || '';

        if (!guardado) {
          return responder(res, 400, {
            erro: 'Nao ha nenhum codigo por confirmar. Pede um novo.'
          });
        }

        if (expira && new Date(expira) < new Date()) {
          return responder(res, 410, {
            erro: 'O codigo expirou. Carrega em reenviar para receberes outro.',
            expirado: true
          });
        }

        if (!iguais(guardado, codigo)) {
          return responder(res, 401, {
            erro: 'Codigo errado. Confere o email e tenta outra vez.'
          });
        }

        bubble('PATCH', '/user/' + encodeURIComponent(u.id), {
          'Token Confirmado': true,
          'Token': ''
        }, function (e3) {
          if (e3) return responder(res, 502, { erro: e3.message });

          const m = emailBemVindo(u.nome);
          enviarEmail(u.email, 'Bem-vindo a Bag Security', m.html, m.texto, function () {});

          responder(res, 200, { ok: true, nome: u.nome });
        });
      });
    });
  }

  if (rota === '/plan-warnings' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });

      const chave = String(p.key || '');
      if (!SEGREDO || chave !== SEGREDO) {
        return responder(res, 403, { erro: 'Nao autorizado.' });
      }

      const limite = new Date(Date.now() + 3 * 86400000).toISOString();
      const c = [
        { key: 'Plan Expires', constraint_type: 'less than', value: limite },
        { key: 'Is Active', constraint_type: 'equals', value: true }
      ];

      bubble('GET', '/user' + constraints(c) + '&limit=100', null, function (e2, j) {
        if (e2) return responder(res, 502, { erro: e2.message });
        const lista = (((j || {}).response || {}).results || []);

        if (!lista.length) return responder(res, 200, { ok: true, avisados: 0 });

        let feitos = 0, falhas = 0;

        lista.forEach(function (d) {
          const u = moldarUtilizador(d);
          if (!u.email || u.dias === null) { feitos++; return; }
          if (u.dias > 3) { feitos++; return; }

          const m = emailAviso(u.nome, u.dias);
          enviarEmail(u.email, u.dias <= 0
            ? 'O teu plano Bag Security expirou'
            : 'O teu plano Bag Security esta a acabar',
            m.html, m.texto, function (e3) {
            if (e3) falhas++;
            feitos++;
            if (feitos === lista.length) {
              responder(res, 200, { ok: true, avisados: feitos - falhas, falhas: falhas });
            }
          });
        });

        setTimeout(function () {
          if (feitos === lista.length && !res.headersSent) {
            responder(res, 200, { ok: true, avisados: 0 });
          }
        }, 200);
      });
    });
  }

  if (rota === '/mail-status' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });

      bubble('GET', '/user/' + encodeURIComponent(dono), null, function (e2, j) {
        if (e2) return responder(res, 403, { erro: 'Utilizador nao encontrado.' });
        const d = (j && j.response) || j;
        const u = moldarUtilizador(d);
        responder(res, 200, {
          ok: true,
          email: u.email,
          confirmado: d['Token Confirmado'] === true,
          nome: u.nome
        });
      });
    });
  }

  /* ================= PLAYLISTS ================= */

  if (rota === '/playlists' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        const c = [
          { key: 'Owner', constraint_type: 'equals', value: u.id },
          { key: 'Is Deleted', constraint_type: 'equals', value: false }
        ];

        bubble('GET', '/playlist' + constraints(c) + '&limit=100&sort_field=Created Date&descending=true',
          null, function (e3, j) {
          if (e3) return responder(res, 502, { erro: e3.message });

          const listas = (((j || {}).response || {}).results || []).map(function (x) {
            const ids = String(x['Track IDs'] || '').split(',')
              .map(function (s) { return s.trim(); })
              .filter(Boolean);
            return {
              id: x._id,
              nome: x['Name'] || '',
              tipo: x['Kind'] || 'mix',
              faixas: ids.length,
              criado: x['Created Date'] || ''
            };
          });

          responder(res, 200, { ok: true, listas: listas });
        });
      });
    });
  }

  if (rota === '/playlist' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const id = String(p.id || '').trim();
      if (!dono || !id) return responder(res, 400, { erro: 'Dados em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        bubble('GET', '/playlist/' + encodeURIComponent(id), null, function (e3, jl) {
          if (e3) return responder(res, 404, { erro: 'Lista nao encontrada.' });
          const l = (jl && jl.response) || jl;
          if (String(l['Owner']) !== String(u.id)) {
            return responder(res, 403, { erro: 'Esta lista nao e tua.' });
          }

          const ids = String(l['Track IDs'] || '').split(',')
            .map(function (s) { return s.trim(); })
            .filter(Boolean);

          if (!ids.length) {
            return responder(res, 200, {
              ok: true, id: l._id, nome: l['Name'] || '',
              tipo: l['Kind'] || 'mix', faixas: []
            });
          }

          const cs = [
            { key: 'Owner', constraint_type: 'equals', value: u.id },
            { key: 'Is Deleted', constraint_type: 'equals', value: false }
          ];

          bubble('GET', '/stored file' + constraints(cs) + '&limit=200', null, function (e4, jf) {
            if (e4) return responder(res, 502, { erro: e4.message });
            const todos = (((jf || {}).response || {}).results || []);

            const mapa = {};
            todos.forEach(function (f) { mapa[f._id] = f; });

            const faixas = [];
            ids.forEach(function (fid) {
              if (mapa[fid]) faixas.push(mapear(mapa[fid]));
            });

            responder(res, 200, {
              ok: true, id: l._id, nome: l['Name'] || '',
              tipo: l['Kind'] || 'mix', faixas: faixas
            });
          });
        });
      });
    });
  }

  if (rota === '/playlist-save' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const nome = limparNome(p.name);
      const id = String(p.id || '').trim();
      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });
      if (!id && !nome) return responder(res, 400, { erro: 'Escreve um nome para a lista.' });

      const ids = (Array.isArray(p.tracks) ? p.tracks : [])
        .map(function (s) { return String(s || '').trim(); })
        .filter(Boolean)
        .slice(0, 300);

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        const tipo = ['audio', 'video', 'mix'].indexOf(String(p.kind || '')) !== -1
          ? String(p.kind) : 'mix';

        if (id) {
          return bubble('GET', '/playlist/' + encodeURIComponent(id), null, function (e3, jl) {
            if (e3) return responder(res, 404, { erro: 'Lista nao encontrada.' });
            const l = (jl && jl.response) || jl;
            if (String(l['Owner']) !== String(u.id)) {
              return responder(res, 403, { erro: 'Esta lista nao e tua.' });
            }

            const mudanca = {};
            if (nome) mudanca['Name'] = nome;
            if (p.tracks !== undefined) mudanca['Track IDs'] = ids.join(',');
            if (p.kind) mudanca['Kind'] = tipo;

            bubble('PATCH', '/playlist/' + encodeURIComponent(id), mudanca, function (e4) {
              if (e4) return responder(res, 502, { erro: e4.message });
              responder(res, 200, { ok: true, id: id, nome: nome || l['Name'] || '' });
            });
          });
        }

        bubble('POST', '/playlist', {
          'Name': nome,
          'Owner': u.id,
          'Kind': tipo,
          'Track IDs': ids.join(','),
          'Is Deleted': false
        }, function (e5, j) {
          if (e5) return responder(res, 502, { erro: e5.message });
          responder(res, 200, { ok: true, id: j.id || '', nome: nome });
        });
      });
    });
  }

  if (rota === '/playlist-add' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const id = String(p.id || '').trim();
      const novos = (Array.isArray(p.tracks) ? p.tracks : [String(p.track || '')])
        .map(function (s) { return String(s || '').trim(); })
        .filter(Boolean);

      if (!dono || !id) return responder(res, 400, { erro: 'Dados em falta.' });
      if (!novos.length) return responder(res, 400, { erro: 'Nenhuma faixa indicada.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        bubble('GET', '/playlist/' + encodeURIComponent(id), null, function (e3, jl) {
          if (e3) return responder(res, 404, { erro: 'Lista nao encontrada.' });
          const l = (jl && jl.response) || jl;
          if (String(l['Owner']) !== String(u.id)) {
            return responder(res, 403, { erro: 'Esta lista nao e tua.' });
          }

          const actuais = String(l['Track IDs'] || '').split(',')
            .map(function (s) { return s.trim(); })
            .filter(Boolean);

          let juntos = 0;
          novos.forEach(function (n) {
            if (actuais.indexOf(n) === -1 && actuais.length < 300) {
              actuais.push(n);
              juntos++;
            }
          });

          if (!juntos) {
            return responder(res, 200, {
              ok: true, juntos: 0, total: actuais.length,
              nome: l['Name'] || '', ja_estava: true
            });
          }

          bubble('PATCH', '/playlist/' + encodeURIComponent(id), {
            'Track IDs': actuais.join(',')
          }, function (e4) {
            if (e4) return responder(res, 502, { erro: e4.message });
            responder(res, 200, {
              ok: true, juntos: juntos, total: actuais.length, nome: l['Name'] || ''
            });
          });
        });
      });
    });
  }

  if (rota === '/playlist-delete' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      const id = String(p.id || '').trim();
      if (!dono || !id) return responder(res, 400, { erro: 'Dados em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        bubble('GET', '/playlist/' + encodeURIComponent(id), null, function (e3, jl) {
          if (e3) return responder(res, 404, { erro: 'Lista nao encontrada.' });
          const l = (jl && jl.response) || jl;
          if (String(l['Owner']) !== String(u.id)) {
            return responder(res, 403, { erro: 'Esta lista nao e tua.' });
          }

          bubble('DELETE', '/playlist/' + encodeURIComponent(id), null, function (e4) {
            if (e4) return responder(res, 502, { erro: e4.message });
            responder(res, 200, { ok: true });
          });
        });
      });
    });
  }

  if (rota === '/media' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });
      const dono = String(p.owner || '').trim();
      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        const cs = [
          { key: 'Owner', constraint_type: 'equals', value: u.id },
          { key: 'Is Deleted', constraint_type: 'equals', value: false }
        ];

        buscarTudo('/stored file', cs, '&sort_field=Created Date&descending=true', function (e3, todos) {
          if (e3) return responder(res, 502, { erro: e3.message });

          const audio = [], video = [];
          todos.forEach(function (f) {
            const t = f['File Type'];
            if (t === 'Audio') audio.push(mapear(f));
            else if (t === 'Video' && f['Status'] === 'Ready') video.push(mapear(f));
          });

          responder(res, 200, { ok: true, audio: audio, video: video });
        });
      });
    });
  }

  if (rota === '/search' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });

      const dono = String(p.owner || '').trim();
      const termo = String(p.q || '').trim().toLowerCase();
      if (!dono) return responder(res, 403, { erro: 'Utilizador em falta.' });
      if (termo.length < 2) {
        return responder(res, 200, { ok: true, ficheiros: [], pastas: [], termo: termo });
      }

      carregarUtilizador(dono, function (e2, u) {
        if (e2) return responder(res, 403, { erro: e2.message });

        const naLixeira = p.trash === true;

        const cs = [
          { key: 'Owner', constraint_type: 'equals', value: u.id },
          { key: 'Is Deleted', constraint_type: 'equals', value: naLixeira }
        ];

        buscarTudo('/stored file', cs, '&sort_field=Created Date&descending=true', function (e3, todos) {
          if (e3) return responder(res, 502, { erro: e3.message });

          const achados = todos.filter(function (f) {
            const nome = String(f['Original Name'] || f['Name'] || '').toLowerCase();
            const ext = String(f['Extension'] || '').toLowerCase();
            return nome.indexOf(termo) !== -1 || ext === termo;
          });

          const cp = [
            { key: 'Owner', constraint_type: 'equals', value: u.id },
            { key: 'Is Deleted', constraint_type: 'equals', value: false }
          ];

          bubble('GET', '/folder' + constraints(cp) + '&limit=200&sort_field=Name',
            null, function (e4, jp) {
            const pastas = e4 ? [] :
              (((jp || {}).response || {}).results || [])
                .filter(function (d) {
                  return String(d['Name'] || '').toLowerCase().indexOf(termo) !== -1;
                })
                .map(function (d) {
                  return { id: d._id, nome: d['Name'] || '', caminho: d['Path'] || '' };
                });

            responder(res, 200, {
              ok: true,
              termo: termo,
              ficheiros: achados.slice(0, 120).map(mapear),
              pastas: pastas.slice(0, 30),
              total: achados.length
            });
          });
        });
      });
    });
  }
    /* ---------- ESTADO DO PAGAMENTO CARTÃO ---------- */
  if (rota === '/payment-status' && metodo === 'POST') {
    return lerJson(req, function (err, p) {
      if (err) return responder(res, 400, { erro: 'JSON invalido.' });

      var referencia = String(p.reference || '').trim();
      if (!referencia) return responder(res, 400, { erro: 'Referencia em falta.' });

      var c = [{ key: 'reference', constraint_type: 'equals', value: referencia }];
      bubble('GET', '/card_payment_pending' + constraints(c) + '&limit=1', null, function (e2, j2) {
        if (e2) return responder(res, 502, { erro: 'Erro ao procurar pagamento.' });

        var lista = (((j2 || {}).response || {}).results || []);
        if (!lista.length) return responder(res, 404, { erro: 'Pagamento nao encontrado.', status: 'not_found' });

        var pendente = lista[0];
        var status = String(pendente['status'] || 'pending').toLowerCase();

        responder(res, 200, { ok: true, status: status, referencia: referencia });
      });
    });
  }

  responder(res, 404, { erro: 'Caminho desconhecido.', rota: rota });
});

servidor.timeout = 0;
servidor.headersTimeout = 0;
servidor.requestTimeout = 0;

servidor.listen(PORTA, function () {
  console.log('bagsecurity-proxy a escutar na porta ' + PORTA);
});
