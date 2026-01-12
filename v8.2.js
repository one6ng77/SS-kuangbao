import { connect } from 'cloudflare:sockets';

// ============ 常量（编译时内联） ============
const UUID = new Uint8Array([
  0x55, 0xd9, 0xec, 0x38, 0x1b, 0x8a, 0x45, 0x4b,
  0x98, 0x1a, 0x6a, 0xcf, 0xe8, 0xf5, 0x6d, 0x8c
]);
const PROXY_HOST = 'sjc.o00o.ooo';
const PROXY_PORT = 443;

const WS_HI = 32768;
const WS_LO = 16384;
const MERGE_MAX = 16384;
const BATCH_HI = 8;
const BATCH_LO = 2;
const BP_LIMIT = 20;
const TIMEOUT = 2000;
const Q_SHIFT = 5;
const Q_SIZE = 32;
const Q_MASK = 31;
const QB_MAX = 262144;

const DEC = new TextDecoder();
const EMPTY = new Uint8Array(0);

const R400 = new Response(null, {status: 400});
const R403 = new Response(null, {status: 403});
const R426 = new Response(null, {status: 426, headers: {Upgrade: 'websocket'}});
const R502 = new Response(null, {status: 502});

// ============ 单态对象（内存对齐） ============
function VLESSResult() {
  this.ok = false;
  this.host = '';
  this.port = 0;
  this.off = 0;
}

const VFAIL = Object.freeze(new VLESSResult());
const B64FAIL = new Uint8Array(0);

// ============ Base64（16字节展开 + 分支消除） ============
function b64dec(s) {
  let bin;
  try {
    bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  } catch {
    return B64FAIL;
  }
  
  const len = bin.length | 0;
  if (len === 0) return B64FAIL;
  
  const out = new Uint8Array(len);
  const end16 = (len & ~15) | 0;
  
  let i = 0;
  while (i < end16) {
    out[i] = bin.charCodeAt(i) | 0;
    out[i+1] = bin.charCodeAt(i+1) | 0;
    out[i+2] = bin.charCodeAt(i+2) | 0;
    out[i+3] = bin.charCodeAt(i+3) | 0;
    out[i+4] = bin.charCodeAt(i+4) | 0;
    out[i+5] = bin.charCodeAt(i+5) | 0;
    out[i+6] = bin.charCodeAt(i+6) | 0;
    out[i+7] = bin.charCodeAt(i+7) | 0;
    out[i+8] = bin.charCodeAt(i+8) | 0;
    out[i+9] = bin.charCodeAt(i+9) | 0;
    out[i+10] = bin.charCodeAt(i+10) | 0;
    out[i+11] = bin.charCodeAt(i+11) | 0;
    out[i+12] = bin.charCodeAt(i+12) | 0;
    out[i+13] = bin.charCodeAt(i+13) | 0;
    out[i+14] = bin.charCodeAt(i+14) | 0;
    out[i+15] = bin.charCodeAt(i+15) | 0;
    i = (i + 16) | 0;
  }
  while (i < len) {
    out[i] = bin.charCodeAt(i) | 0;
    i = (i + 1) | 0;
  }
  
  return out;
}

// ============ UUID（8x2展开 + 短路优化） ============
function chkUUID(d, o) {
  const o0 = o | 0;
  const d0 = d[o0] ^ UUID[0];
  const d1 = d[o0+1] ^ UUID[1];
  const d2 = d[o0+2] ^ UUID[2];
  const d3 = d[o0+3] ^ UUID[3];
  if ((d0 | d1 | d2 | d3) !== 0) return false;
  
  const d4 = d[o0+4] ^ UUID[4];
  const d5 = d[o0+5] ^ UUID[5];
  const d6 = d[o0+6] ^ UUID[6];
  const d7 = d[o0+7] ^ UUID[7];
  if ((d4 | d5 | d6 | d7) !== 0) return false;
  
  const d8 = d[o0+8] ^ UUID[8];
  const d9 = d[o0+9] ^ UUID[9];
  const d10 = d[o0+10] ^ UUID[10];
  const d11 = d[o0+11] ^ UUID[11];
  if ((d8 | d9 | d10 | d11) !== 0) return false;
  
  const d12 = d[o0+12] ^ UUID[12];
  const d13 = d[o0+13] ^ UUID[13];
  const d14 = d[o0+14] ^ UUID[14];
  const d15 = d[o0+15] ^ UUID[15];
  return (d12 | d13 | d14 | d15) === 0;
}

// ============ VLESS（快速路径优先） ============
function parseVL(d) {
  const len = d.length | 0;
  
  if (len < 22) return VFAIL;
  if (d[0] !== 0) return VFAIL;
  if (!chkUUID(d, 1)) return VFAIL;
  
  const alen = d[17] | 0;
  if (alen > 255) return VFAIL;
  
  const coff = (18 + alen) | 0;
  if ((coff + 3) > len) return VFAIL;
  if (d[coff] !== 1) return VFAIL;
  
  const port = ((d[coff+1] << 8) | d[coff+2]) | 0;
  const aoff = (coff + 3) | 0;
  if (aoff >= len) return VFAIL;
  
  const atype = d[aoff] | 0;
  const result = new VLESSResult();
  result.ok = true;
  result.port = port;
  
  // 快速路径：IPv4（最常见）
  if (atype === 1) {
    const end = (aoff + 5) | 0;
    if (end > len) return VFAIL;
    result.host = `${d[aoff+1]}.${d[aoff+2]}.${d[aoff+3]}.${d[aoff+4]}`;
    result.off = end;
    return result;
  }
  
  // 中速路径：Domain
  if (atype === 2) {
    if ((aoff + 2) > len) return VFAIL;
    const dlen = d[aoff+1] | 0;
    const end = (aoff + 2 + dlen) | 0;
    if (end > len) return VFAIL;
    result.host = DEC.decode(d.subarray(aoff + 2, end));
    result.off = end;
    return result;
  }
  
  // 慢速路径：IPv6
  if (atype === 3) {
    const end = (aoff + 17) | 0;
    if (end > len) return VFAIL;
    const v = new DataView(d.buffer, d.byteOffset + aoff + 1, 16);
    result.host = [
      v.getUint16(0).toString(16),
      v.getUint16(2).toString(16),
      v.getUint16(4).toString(16),
      v.getUint16(6).toString(16),
      v.getUint16(8).toString(16),
      v.getUint16(10).toString(16),
      v.getUint16(12).toString(16),
      v.getUint16(14).toString(16)
    ].join(':');
    result.off = end;
    return result;
  }
  
  return VFAIL;
}

// ============ TCP连接 ============
async function dial(host, port, fb) {
  const sock = connect({
    hostname: fb ? PROXY_HOST : host, 
    port: (fb ? PROXY_PORT : port) | 0
  }, {allowHalfOpen: false});
  
  let tid = 0;
  try {
    await Promise.race([
      sock.opened,
      new Promise((_, rej) => { tid = setTimeout(rej, TIMEOUT) | 0; })
    ]);
  } finally {
    if (tid) clearTimeout(tid);
  }
  
  return sock;
}

// ============ 状态 ============
function State(ws, tcp) {
  this.ws = ws;
  this.tcp = tcp;
  this.dead = false;
}

State.prototype.kill = function() {
  if (this.dead) return;
  this.dead = true;
  
  const ws = this.ws;
  const tcp = this.tcp;
  this.ws = null;
  this.tcp = null;
  
  queueMicrotask(() => {
    try { if (ws) ws.close(); } catch {}
    try { if (tcp) tcp.close(); } catch {}
  });
};

// ============ 上行（环形缓冲 + 位运算索引） ============
function Uplink(s, w) {
  this.s = s;
  this.w = w;
  this.q = new Array(Q_SIZE);
  this.qh = 0;
  this.qt = 0;
  this.qb = 0;
  this.lock = false;
}

Uplink.prototype.push = function(chunk) {
  if (this.s.dead) return;
  
  const len = chunk.length | 0;
  const qsize = ((this.qt - this.qh) & Q_MASK) | 0;
  
  if (qsize >= Q_MASK || this.qb > QB_MAX) {
    this.s.kill();
    return;
  }
  
  this.q[this.qt & Q_MASK] = chunk;
  this.qt = (this.qt + 1) | 0;
  this.qb = (this.qb + len) | 0;
  
  const trigger = (len > 8192 | (this.qb >= MERGE_MAX) | (qsize >= 15)) | 0;
  
  if (trigger & ~this.lock) {
    this.drain();
  } else if (!this.lock) {
    queueMicrotask(() => this.drain());
  }
};

Uplink.prototype.drain = async function() {
  if (this.lock | this.s.dead) return;
  
  const qh = this.qh | 0;
  const qt = this.qt | 0;
  if (qh === qt) return;
  
  this.lock = true;
  const s = this.s;
  const w = this.w;
  
  while ((this.qh !== this.qt) & !s.dead) {
    const qsize = ((this.qt - this.qh) & Q_MASK) | 0;
    
    let bc = 0;
    let bb = 0;
    let idx = this.qh | 0;
    
    while ((bc < 16) & (bc < qsize)) {
      const clen = this.q[idx & Q_MASK].length | 0;
      if ((bb > 0) & ((bb + clen) > MERGE_MAX)) break;
      bb = (bb + clen) | 0;
      bc = (bc + 1) | 0;
      idx = (idx + 1) | 0;
    }
    
    let data;
    if (bc === 1) {
      data = this.q[this.qh & Q_MASK];
    } else {
      data = new Uint8Array(bb);
      let off = 0;
      let i = 0;
      while (i < bc) {
        const c = this.q[(this.qh + i) & Q_MASK];
        data.set(c, off);
        off = (off + c.length) | 0;
        i = (i + 1) | 0;
      }
    }
    
    this.qh = (this.qh + bc) | 0;
    this.qb = (this.qb - bb) | 0;
    
    try {
      await w.ready;
      if (s.dead) break;
      await w.write(data);
    } catch {
      s.kill();
      break;
    }
  }
  
  this.lock = false;
};

// ============ 下行（零分配首帧 + 函数内联） ============
function Downlink(s, ws, r) {
  this.s = s;
  this.ws = ws;
  this.r = r;
  this.first = true;
  this.run();
}

Downlink.prototype.run = async function() {
  const s = this.s;
  const ws = this.ws;
  const r = this.r;
  let first = true;
  
  try {
    while (!s.dead) {
      let buf = ws.bufferedAmount | 0;
      
      if (buf > WS_HI) {
        let cnt = 0;
        await new Promise(res => {
          function chk() {
            const dead = s.dead | 0;
            const low = (ws.bufferedAmount < WS_LO) | 0;
            if (dead | low) {
              res();
            } else {
              cnt = (cnt + 1) | 0;
              if (cnt > BP_LIMIT) {
                setTimeout(res, 1);
              } else {
                queueMicrotask(chk);
              }
            }
          }
          chk();
        });
        if (s.dead) break;
      }
      
      buf = ws.bufferedAmount | 0;
      const qt = ((buf < WS_LO) ? BATCH_HI : BATCH_LO) | 0;
      
      let i = 0;
      while ((i < qt) & !s.dead) {
        const {done, value} = await r.read();
        
        if (done) {
          s.kill();
          return;
        }
        
        if (first) {
          const vlen = value.length | 0;
          const frame = new Uint8Array((vlen + 2) | 0);
          frame[0] = 0;
          frame[1] = 0;
          frame.set(value, 2);
          ws.send(frame);
          first = false;
        } else {
          ws.send(value);
        }
        
        i = (i + 1) | 0;
        if (ws.bufferedAmount > WS_HI) break;
      }
    }
  } catch {
    s.kill();
  } finally {
    queueMicrotask(() => {
      try { r.releaseLock(); } catch {}
    });
  }
};

// ============ 事件处理器（函数提升） ============
function onMessage(up, e) {
  up.push(new Uint8Array(e.data));
}

function onClose(s) {
  s.kill();
}

function onError(s) {
  s.kill();
}

// ============ 主入口 ============
export default {
  async fetch(req) {
    if (req.headers.get('Upgrade') !== 'websocket') return R426;
    
    const proto = req.headers.get('Sec-WebSocket-Protocol');
    if (!proto) return R400;
    
    const data = b64dec(proto);
    if (data === B64FAIL) return R400;
    
    const vl = parseVL(data);
    if (!vl.ok) return R403;
    
    let tcp;
    try {
      tcp = await dial(vl.host, vl.port, false);
    } catch {
      try {
        tcp = await dial(vl.host, vl.port, true);
      } catch {
        return R502;
      }
    }
    
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();
    
    const state = new State(server, tcp);
    
    const dlen = data.length | 0;
    const doff = vl.off | 0;
    const init = (dlen > doff) ? data.subarray(doff) : EMPTY;
    
    const up = new Uplink(state, tcp.writable.getWriter());
    if (init.length > 0) up.push(init);
    
    server.addEventListener('message', e => onMessage(up, e));
    server.addEventListener('close', () => onClose(state));
    server.addEventListener('error', () => onError(state));
    
    new Downlink(state, server, tcp.readable.getReader());
    
    return new Response(null, {status: 101, webSocket: client});
  }
};
