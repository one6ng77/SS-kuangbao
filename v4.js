import { connect } from 'cloudflare:sockets';

// ============ 预编译常量 ============
const UUID = new Uint8Array([
  0x55, 0xd9, 0xec, 0x38, 0x1b, 0x8a, 0x45, 0x4b,
  0x98, 0x1a, 0x6a, 0xcf, 0xe8, 0xf5, 0x6d, 0x8c
]);
const PROXY_HOST = 'sjc.o00o.ooo';
const PROXY_PORT = 443;

// 地址类型
const ATYPE_IPV4 = 1;
const ATYPE_DOMAIN = 2;
const ATYPE_IPV6 = 3;

// 流控配置
const WS_HIGH_WATER = 65536;   // 64KB 背压阈值
const WS_BACKOFF_MS = 5;       // 背压等待间隔
const CONNECT_TIMEOUT = 1000;  // 1秒连接超时

// ============ 单例复用 ============
const textDecoder = new TextDecoder();
const EMPTY_BYTES = new Uint8Array(0);

// ============ 类型稳定的返回对象工厂 ============
const createParseResult = (host, end, ok) => ({ host, end, ok });
const createDecodeResult = (data, ok) => ({ data, ok });

// 预分配错误对象 - 避免重复创建
const PARSE_FAIL = Object.freeze(createParseResult('', 0, false));
const DECODE_FAIL = Object.freeze(createDecodeResult(null, false));

// ============ 预编译响应配置 ============
const RESP_101 = (ws) => new Response(null, { status: 101, webSocket: ws });
const RESP_400 = () => new Response(null, { status: 400 });
const RESP_403 = () => new Response(null, { status: 403 });
const RESP_426 = () => new Response(null, { status: 426, headers: { Upgrade: 'websocket' } });
const RESP_502 = () => new Response(null, { status: 502 });

// ============ Base64 URL-safe 解码 ============
const decodeBase64 = (str) => {
  try {
    const binary = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
    const len = binary.length;
    const arr = new Uint8Array(len);
    // 4字节展开循环
    const end4 = len & ~3;
    let i = 0;
    for (; i < end4; i += 4) {
      arr[i] = binary.charCodeAt(i);
      arr[i + 1] = binary.charCodeAt(i + 1);
      arr[i + 2] = binary.charCodeAt(i + 2);
      arr[i + 3] = binary.charCodeAt(i + 3);
    }
    for (; i < len; i++) {
      arr[i] = binary.charCodeAt(i);
    }
    return createDecodeResult(arr, true);
  } catch {
    return DECODE_FAIL;
  }
};

// ============ UUID 验证（SIMD风格位运算优化） ============
const verifyUUID = (data, offset) => {
  // 4字节块并行比较，早期失败
  return (
    ((data[offset] ^ UUID[0]) | (data[offset + 1] ^ UUID[1]) |
     (data[offset + 2] ^ UUID[2]) | (data[offset + 3] ^ UUID[3])) === 0 &&
    ((data[offset + 4] ^ UUID[4]) | (data[offset + 5] ^ UUID[5]) |
     (data[offset + 6] ^ UUID[6]) | (data[offset + 7] ^ UUID[7])) === 0 &&
    ((data[offset + 8] ^ UUID[8]) | (data[offset + 9] ^ UUID[9]) |
     (data[offset + 10] ^ UUID[10]) | (data[offset + 11] ^ UUID[11])) === 0 &&
    ((data[offset + 12] ^ UUID[12]) | (data[offset + 13] ^ UUID[13]) |
     (data[offset + 14] ^ UUID[14]) | (data[offset + 15] ^ UUID[15])) === 0
  );
};

// ============ 标准VLESS地址解析（优化版） ============
const parseAddress = (data, offset, dataLen) => {
  const atype = data[offset];

  // IPv4 - 最常见，优先处理
  if (atype === ATYPE_IPV4) {
    const end = offset + 5;
    if (end > dataLen) return PARSE_FAIL;
    const d = data;
    const o = offset + 1;
    return createParseResult(
      `${d[o]}.${d[o + 1]}.${d[o + 2]}.${d[o + 3]}`,
      end,
      true
    );
  }

  // 域名 - 次常见
  if (atype === ATYPE_DOMAIN) {
    if (offset + 2 > dataLen) return PARSE_FAIL;
    const domainLen = data[offset + 1];
    const end = offset + 2 + domainLen;
    if (end > dataLen) return PARSE_FAIL;
    return createParseResult(
      textDecoder.decode(data.subarray(offset + 2, end)),
      end,
      true
    );
  }

  // IPv6 - 较少使用
  if (atype === ATYPE_IPV6) {
    const end = offset + 17;
    if (end > dataLen) return PARSE_FAIL;
    const dv = new DataView(data.buffer, data.byteOffset + offset + 1, 16);
    // 使用数组join减少字符串拼接
    const parts = new Array(8);
    for (let i = 0; i < 8; i++) {
      parts[i] = dv.getUint16(i * 2).toString(16);
    }
    return createParseResult(parts.join(':'), end, true);
  }

  return PARSE_FAIL;
};

// ============ 超时控制 ============
const withTimeout = (promise, ms) => {
  let tid;
  return Promise.race([
    promise,
    new Promise((_, rej) => { tid = setTimeout(() => rej(new Error('timeout')), ms); })
  ]).finally(() => clearTimeout(tid));
};

// ============ TCP 连接 ============
const connectTCP = async (host, port, fallback) => {
  const socket = connect(
    { hostname: fallback ? PROXY_HOST : host, port: fallback ? PROXY_PORT : port },
    { allowHalfOpen: false }
  );
  await withTimeout(socket.opened, CONNECT_TIMEOUT);
  return socket;
};

// ============ 连接状态（固定形状） ============
class State {
  constructor() {
    this.closed = false;
    this.ws = null;
    this.tcp = null;
  }

  init(ws, tcp) {
    this.ws = ws;
    this.tcp = tcp;
  }

  shutdown() {
    if (this.closed) return;
    this.closed = true;
    try { this.ws?.close(); } catch {}
    try { this.tcp?.close(); } catch {}
  }
}

// ============ VLESS响应头（预分配） ============
const VLESS_RESPONSE_HEADER = new Uint8Array([0x00, 0x00]); // 版本0 + 无附加信息

// ============ 首帧构建（标准VLESS响应） ============
const buildFirstFrame = (chunk) => {
  const frame = new Uint8Array(2 + chunk.length);
  frame.set(VLESS_RESPONSE_HEADER, 0);
  frame.set(chunk, 2);
  return frame;
};

// ============ 上行管道（WebSocket → TCP） ============
const createUplink = (state, initial, writable) => {
  const writer = writable.getWriter();
  let chain = Promise.resolve();

  const write = (chunk) => {
    chain = chain
      .then(() => state.closed ? undefined : writer.write(chunk))
      .catch(() => state.shutdown());
  };

  if (initial.length > 0) write(initial);

  return (ev) => {
    if (!state.closed) write(new Uint8Array(ev.data));
  };
};

// ============ 下行管道（TCP → WebSocket） ============
const createDownlink = (state, ws, readable) => {
  const reader = readable.getReader();
  let first = true;

  (async () => {
    try {
      while (!state.closed) {
        // 背压控制
        while (ws.bufferedAmount > WS_HIGH_WATER && !state.closed) {
          await new Promise(r => setTimeout(r, WS_BACKOFF_MS));
        }
        if (state.closed) break;

        const { done, value } = await reader.read();
        if (done || state.closed) break;

        ws.send(first ? (first = false, buildFirstFrame(value)) : value);
      }
    } catch {
      // 连接异常
    } finally {
      state.shutdown();
      try { reader.releaseLock(); } catch {}
    }
  })();
};

// ============ 标准VLESS协议解析（优化版） ============
const parseVLESSRequest = (data) => {
  const dataLen = data.length;

  // 快速失败：最小长度检查（版本1 + UUID16 + 附加长度1 + 指令1 + 端口2 + 地址类型1）
  if (dataLen < 22 || data[0] !== 0x00) return null;

  // UUID验证（早期失败）
  if (!verifyUUID(data, 1)) return null;

  // 计算指令偏移（附加信息长度在偏移17）
  const addonsLen = data[17];
  const cmdOffset = 18 + addonsLen;

  // 边界检查 + 指令验证（合并）
  if (cmdOffset + 3 > dataLen) return null;
  const cmd = data[cmdOffset];
  if ((cmd & 0xFE) !== 0) return null; // 快速检查：只允许0x01或0x02

  // 使用位运算读取端口（避免多次数组访问）
  const port = (data[cmdOffset + 1] << 8) | data[cmdOffset + 2];

  // 地址解析（传入dataLen避免重复访问）
  const addrOffset = cmdOffset + 3;
  if (addrOffset >= dataLen) return null;

  const addr = parseAddress(data, addrOffset, dataLen);
  if (!addr.ok) return null;

  return {
    cmd,
    port,
    host: addr.host,
    dataOffset: addr.end
  };
};

// ============ 主处理器 ============
export default {
  async fetch(req) {
    // 快速路径检查
    if (req.headers.get('Upgrade') !== 'websocket') return RESP_426();

    const protocol = req.headers.get('Sec-WebSocket-Protocol');
    if (!protocol) return RESP_400();

    // 解码 payload
    const decoded = decodeBase64(protocol);
    if (!decoded.ok) return RESP_400();
    const data = decoded.data;

    // 标准VLESS协议解析
    const vlessReq = parseVLESSRequest(data);
    if (!vlessReq) return RESP_403();

    // 仅支持TCP指令
    if (vlessReq.cmd !== 0x01) return RESP_400();

    // TCP 连接（回退机制）
    let tcp;
    try {
      tcp = await connectTCP(vlessReq.host, vlessReq.port, false);
    } catch {
      try {
        tcp = await connectTCP(vlessReq.host, vlessReq.port, true);
      } catch {
        return RESP_502();
      }
    }

    // WebSocket 握手
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    // 初始化状态
    const state = new State();
    state.init(server, tcp);

    // 初始数据（VLESS协议头之后的数据）
    const initial = data.length > vlessReq.dataOffset ? data.subarray(vlessReq.dataOffset) : EMPTY_BYTES;

    // 建立管道
    const onMessage = createUplink(state, initial, tcp.writable);
    server.addEventListener('message', onMessage);
    server.addEventListener('close', () => state.shutdown());
    server.addEventListener('error', () => state.shutdown());
    createDownlink(state, server, tcp.readable);

    return RESP_101(client);
  }
};
