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

/* ============ API do Bunny Stream ============ */

function stream(metodo, caminho, corpo, cb) {
  if (!STREAM_LIB || !STREAM_KEY) return cb(new Error('Stream nao configurado.'));

  const payload = corpo ? JSON.stringify(corpo) : null;
  const opcoes = {
    hostname: 'video.bunnycdn.com',
    path: '/library/' + STREAM_LIB + caminho,
    method: metodo,
    headers: {
      'AccessKey': STREAM_KEY,
      'Content-Type': 'application/json',
      'accept': 'application/json'
    }
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
      try { cb(null, JSON.parse(texto)); }
      catch (e) { cb(null, {}); }
    });
  });

  pedido.setTimeout(20000, function () { pedido.destroy(new Error('Stream demorou demasiado.')); });
  pedido.on('error', function (e) { cb(e); });
  if (payload) pedido.write(payload);
  pedido.end();
}

/* assinatura TUS: sha256 de libraryId + apiKey + expira + videoId */
function assinaturaTus(videoId, expira) {
  return crypto.createHash('sha256')
    .update(STREAM_LIB + STREAM_KEY + expira + videoId)
    .digest('hex');
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
  if (!CDN) return '';
  const limpo = '/' + encodeURI(caminho);
  if (!CDN_KEY) return 'https://' + CDN + limpo;

  const expira = Math.floor(Date.now() / 1000) + (segundos || 3600);
  const hash = crypto.createHash('sha256').update(CDN_KEY + limpo + expira).digest('base64')
    .replace(/\n/g, '').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  return 'https://' + CDN + limpo + '?token=' + hash + '&expires=' + expira;
}

/* ============ apagar no Bunny ============ */

function apagarNoBunny(caminho, cb) {
  if (!caminho) return cb(null, 404);
  const p = https.request({
    hostname: HOST,
    path: '/' + ZONE + '/' + encodeURI(caminho),
    method: 'DELETE',
    headers: { 'AccessKey': PASS }
  }, function (r) {
    r.resume();
    r.on('end', function () { cb(null, r.statusCode); });
  });
  p.setTimeout(15000, function () { p.destroy(); });
  p.on('error', function (e) { cb(e); });
  p.end();
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

/* ============ mapear ficheiro ============ */

function mapear(f) {
  const noStream = f['Storage Type'] === 'Bunny Stream';
  const vid = f['Bunny Video ID'] || '';

  return {
    id: f._id,
    nome: f['Original Name'] || f['Name'] || '',
    ext: f['Extension'] || '',
    tipo: f['File Type'] || 'Other',
    mime: f['MIME Type'] || '',
    tamanho: Number(f['Size Bytes'] || 0),
    caminho: f['Bunny Path'] || '',
    estado: f['Status'] || 'Ready',
    stream: noStream,
    video_id: vid,
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
    criado: f['Created Date'] || ''
  };
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
      versao: 'container-5',
      storage: Boolean(ZONE && PASS && HOST),
      bubble: Boolean(BUBBLE_BASE && BUBBLE_TOKEN),
      cdn_assinado: Boolean(CDN_KEY),
      stream: Boolean(STREAM_LIB && STREAM_KEY && STREAM_CDN)
    });
  }

  /* ---------- planos ---------- */
  if (rota === '/plans' && metodo === 'POST') {
    const c = [{ key: 'Is Active', constraint_type: 'equals', value: true }];
    return bubble('GET', '/plan' + constraints(c) + '&limit=50&sort_field=Sort Order', null, function (e, j) {
      if (e) return responder(res, 502, { erro: e.message });
      const lista = (((j || {}).response || {}).results || []).map(function (p) {
        return {
          id: p._id, nome: p['Name'] || '', label: p['Storage Label'] || '',
          limite: Number(p['Storage Limit Bytes'] || 0),
          maxFicheiro: Number(p['Max File Size Bytes'] || 0),
          maxVideo: Number(p['Max Video Size Bytes'] || 0),
          preco: Number(p['Price MZN'] || 0),
          utilizadores: Number(p['Max Users'] || 1),
          partilha: p['Allows Sharing'] === true,
          ordem: Number(p['Sort Order'] || 0)
        };
      });
      responder(res, 200, { ok: true, planos: lista });
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
            ok: true,
            total: todos.length,
            contagem: contagem,
            bytes: bytes,
            partilhados: todos.filter(function (f) { return f['Is Shared'] === true; }).length,
            recentes: todos.slice(0, 8).map(mapear),
            usado: u.usado, limite: u.limite
          });
        });
      });
    });
  }

  /* ---------- token de upload (Storage ou Stream) ---------- */
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
        if (u.maxFicheiro > 0 && tamanho > u.maxFicheiro) {
          return responder(res, 403, { erro: 'Ficheiro acima do limite do plano.' });
        }
        if (u.limite > 0 && tamanho > (u.limite - u.usado)) {
          return responder(res, 403, { erro: 'Sem espaco suficiente.' });
        }

        /* ----- caminho Stream ----- */
        if (video) {
          return stream('POST', '/videos', { title: limparNome(nomeBruto) }, function (e3, v) {
            if (e3) return responder(res, 502, { erro: e3.message });
            const vid = v && v.guid;
            if (!vid) return responder(res, 502, { erro: 'O Stream nao devolveu o video.' });

            const expira = Math.floor(Date.now() / 1000) + 7200;
            responder(res, 200, {
              ok: true,
              modo: 'stream',
              video_id: vid,
              library: STREAM_LIB,
              expires: expira,
              signature: assinaturaTus(vid, expira),
              endpoint: 'https://video.bunnycdn.com/tusupload'
            });
          });
        }

        /* ----- caminho Storage ----- */
        const dono = limpar(u.id);
        const unico = Date.now() + '-' + Math.floor(Math.random() * 100000) + '-' + nome;
        const caminho = dono + (pasta ? '/' + pasta : '') + '/' + unico;
        const expira = Math.floor(Date.now() / 1000) + 7200;
        const token = expira + '.' + tamanho + '.' + assinar(caminho + '|' + expira + '|' + tamanho);

        responder(res, 200, { ok: true, modo: 'storage', token: token, path: caminho, expires: expira });
      });
    });
  }

  /* ---------- enviar para o Storage ---------- */
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
      hostname: HOST,
      path: '/' + ZONE + '/' + encodeURI(caminho),
      method: 'PUT',
      headers: { 'AccessKey': PASS, 'Content-Type': tipo }
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

  /* ---------- registar ---------- */
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
          'Is Deleted': false,
          'Is Shared': false
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

  /* ---------- estado de um video ---------- */
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
              ok: true,
              estado: novo,
              progresso: Number(v.encodeProgress || 0),
              duracao: Number(v.length || 0),
              largura: Number(v.width || 0),
              altura: Number(v.height || 0)
            });
          });
        });
      });
    });
  }

  /* ---------- listar ---------- */
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
        const recentes = !lixo && p.recent === true;
        const global = porTipo || soPartilhados || recentes;

        const cf = [
          { key: 'Owner', constraint_type: 'equals', value: u.id },
          { key: 'Is Deleted', constraint_type: 'equals', value: lixo }
        ];
        if (porTipo) cf.push({ key: 'File Type', constraint_type: 'equals', value: String(p.type) });
        if (soPartilhados) cf.push({ key: 'Is Shared', constraint_type: 'equals', value: true });

        if (!global && !lixo) {
          if (p.folder_id) cf.push({ key: 'Folder', constraint_type: 'equals', value: String(p.folder_id) });
          else cf.push({ key: 'Folder', constraint_type: 'is_empty' });
        }

        const ordem = '&sort_field=Created Date&descending=true';

        bubble('GET', '/stored file' + constraints(cf) + '&limit=100' + ordem, null, function (e3, jf) {
          if (e3) return responder(res, 502, { erro: e3.message });
          const ficheiros = (((jf || {}).response || {}).results || []).map(mapear);

          if (global || lixo) {
            return responder(res, 200, {
              ok: true, pastas: [], ficheiros: ficheiros, usado: u.usado, limite: u.limite
            });
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
            responder(res, 200, {
              ok: true, pastas: pastas, ficheiros: ficheiros, usado: u.usado, limite: u.limite
            });
          });
        });
      });
    });
  }

  /* ---------- apagar ---------- */
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
                responder(res, 200, { ok: true, definitivo: true, usado: novo });
              });
            });
          }

          const vid = f['Bunny Video ID'];
          if (vid) return stream('DELETE', '/videos/' + encodeURIComponent(vid), null, function () { terminar(); });
          apagarNoBunny(f['Bunny Path'] || '', function () { terminar(); });
        });
      });
    });
  }

  /* ---------- restaurar ---------- */
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

  /* ---------- renomear ---------- */
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
            const vid = !ePasta && d['Bunny Video ID'];
            if (vid) stream('POST', '/videos/' + encodeURIComponent(vid), { title: nome }, function () {});
            responder(res, 200, { ok: true, nome: nome });
          });
        });
      });
    });
  }

  /* ---------- mover ---------- */
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

  /* ---------- criar pasta ---------- */
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

  /* ---------- partilhar ---------- */
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

  /* ---------- abrir partilha ---------- */
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

  /* ---------- link assinado ---------- */
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

  responder(res, 404, { erro: 'Caminho desconhecido.', rota: rota });
});

servidor.timeout = 0;
servidor.headersTimeout = 0;
servidor.requestTimeout = 0;

servidor.listen(PORTA, function () {
  console.log('bagsecurity-proxy a escutar na porta ' + PORTA);
});
