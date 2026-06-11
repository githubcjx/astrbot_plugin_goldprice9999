"""AstrBot 插件：查询黄金9999（Au99.99）实时金价。

数据来源：融通金 H5 行情（i.jzj9999.com）所使用的实时行情网关。
该网关为 WebSocket + Protobuf 二进制协议，连接后需用 Blowfish/CBC 加密的
token 进行鉴权，鉴权成功后订阅合约即可收到实时推送。

本文件不依赖 protobuf 运行库，内置了一个仅覆盖本场景所需字段的极简
protobuf 编解码器；加密使用 pycryptodome 的 Blowfish（标准实现，与服务端一致）。
"""

import asyncio
import struct
import time

import aiohttp
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad

from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger, AstrBotConfig

# ---------------------------------------------------------------------------
# 行情网关常量（自融通金 H5 前端逆向得到）
# ---------------------------------------------------------------------------
WS_URL = "wss://rtjwbqt.ytj9999.com:8443/gateway"
ORIGIN = "https://i.jzj9999.com"
USER_AGENT = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
)

AUTH_APPTYPE = "rtj"
AUTH_VERIFYCODE = "plaintract"
AUTH_KEY = b"tdc5%y4yaU@xFi"
AUTH_IV = b"5X4f$^hp"

# QuoteMsgID 枚举
MSG_AUTH = 32
MSG_LATEST = 18

GOLD_CODE = "Au99.99"
GOLD_NAME = "黄金9999"

# Blowfish 自检向量：固定明文 "plaintractrtj1700000000000" 的预期密文。
# 若 pycryptodome 的 Blowfish 与服务端不一致，鉴权必然失败，借此提前发现。
_SELFTEST_PLAINTEXT = b"plaintractrtj1700000000000"
_SELFTEST_CIPHER_HEX = (
    "3dd5f93853bc8590cf6227aa02f97d2f7bb8e0a43c0215eb0e13440ee9940d31"
)


# ---------------------------------------------------------------------------
# 极简 protobuf 编码（仅本插件所需）
# ---------------------------------------------------------------------------
def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _tag(field: int, wire: int) -> bytes:
    return _varint((field << 3) | wire)


def _ld(field: int, data: bytes) -> bytes:
    """length-delimited 字段（string / bytes / 嵌套 message）。"""
    return _tag(field, 2) + _varint(len(data)) + data


def _str_field(field: int, s: str) -> bytes:
    return _ld(field, s.encode("utf-8"))


def _varint_field(field: int, n: int) -> bytes:
    return _tag(field, 0) + _varint(n)


def _sint_field(field: int, n: int) -> bytes:
    """sint32（zigzag 编码）。"""
    zz = (n << 1) ^ (n >> 31)
    return _tag(field, 0) + _varint(zz & 0xFFFFFFFF)


# ---------------------------------------------------------------------------
# 极简 protobuf 解码
# ---------------------------------------------------------------------------
def _read_varint(buf, pos):
    shift = 0
    result = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def _iter_fields(buf):
    """逐字段产出 (field_number, wire_type, value)。

    value：wire_type 0 为 int；其余为对应的原始 bytes。
    """
    pos = 0
    n = len(buf)
    while pos < n:
        key, pos = _read_varint(buf, pos)
        fn = key >> 3
        wt = key & 7
        if wt == 0:
            val, pos = _read_varint(buf, pos)
            yield fn, wt, val
        elif wt == 1:  # 64-bit
            yield fn, wt, buf[pos:pos + 8]
            pos += 8
        elif wt == 2:  # length-delimited
            ln, pos = _read_varint(buf, pos)
            yield fn, wt, buf[pos:pos + ln]
            pos += ln
        elif wt == 5:  # 32-bit
            yield fn, wt, buf[pos:pos + 4]
            pos += 4
        else:  # 未知 wire type，无法继续安全解析
            return


def _f64(b: bytes):
    return struct.unpack("<d", b)[0] if len(b) == 8 else None


def _packed_doubles(b: bytes):
    return [struct.unpack("<d", b[i:i + 8])[0] for i in range(0, len(b) - 7, 8)]


# ---------------------------------------------------------------------------
# 报文构造
# ---------------------------------------------------------------------------
def _make_token() -> bytes:
    plaintext = f"{AUTH_VERIFYCODE}{AUTH_APPTYPE}{int(time.time() * 1000)}".encode("utf-8")
    cipher = Blowfish.new(AUTH_KEY, Blowfish.MODE_CBC, AUTH_IV)
    return cipher.encrypt(pad(plaintext, Blowfish.block_size))


def _build_auth() -> bytes:
    # QuotationRequest.auth = AuthReq{apptype, token}
    auth_req = _str_field(1, AUTH_APPTYPE) + _ld(2, _make_token())
    request = _ld(5, auth_req)
    # QuotationMsg{msgid=auth, seq=0, request}
    return _varint_field(1, MSG_AUTH) + _sint_field(2, 0) + _ld(4, request)


def _build_subscribe() -> bytes:
    # QuotationRequest{codes=[Au99.99], freq=[REALTIME(0)]}
    request = _str_field(1, GOLD_CODE) + _varint_field(2, 0)
    # QuotationMsg{msgid=latestQuotation, seq=1, request}
    return _varint_field(1, MSG_LATEST) + _sint_field(2, 1) + _ld(4, request)


# ---------------------------------------------------------------------------
# 报文解析
# ---------------------------------------------------------------------------
def _parse_realtime(buf) -> dict:
    rt = {}
    for fn, wt, val in _iter_fields(buf):
        if fn == 1 and wt == 1:
            rt["last"] = _f64(val)
        elif fn == 2:  # askPrice（卖盘，packed 或 repeated double）
            rt["ask"] = _packed_doubles(val) if wt == 2 else [_f64(val)]
        elif fn == 4:  # bidPrice（买盘）
            rt["bid"] = _packed_doubles(val) if wt == 2 else [_f64(val)]
        elif fn == 11 and wt == 1:
            rt["updown"] = _f64(val)
        elif fn == 12 and wt == 1:
            rt["updown_rate"] = _f64(val)
    return rt


def _parse_field(buf) -> dict:
    d = {}
    for fn, wt, val in _iter_fields(buf):
        if fn == 1 and wt == 2:
            d["code"] = val.decode("utf-8", "ignore")
        elif fn == 7 and wt == 2:
            d["rt"] = _parse_realtime(val)
        elif fn == 8 and wt == 1:
            d["open"] = _f64(val)
        elif fn == 9 and wt == 1:
            d["high"] = _f64(val)
        elif fn == 10 and wt == 1:
            d["low"] = _f64(val)
        elif fn == 13 and wt == 1:
            d["pre_close"] = _f64(val)
    return d


def _decode_message(buf):
    """解析一条 QuotationMsg，返回 (是否含鉴权回执, 目标合约行情或 None)。"""
    authed = False
    quote = None
    for fn, wt, val in _iter_fields(buf):
        if fn != 5 or wt != 2:  # QuotationResponse（repeated）
            continue
        for rfn, rwt, rval in _iter_fields(val):
            if rfn == 5 and rwt == 2:          # AuthResp 存在 -> 鉴权成功
                authed = True
            elif rfn == 1 and rwt == 2:        # QuotationField
                field = _parse_field(rval)
                if field.get("code") == GOLD_CODE:
                    quote = field
    return authed, quote


# ---------------------------------------------------------------------------
# 行情拉取
# ---------------------------------------------------------------------------
async def fetch_gold_quote(timeout: float = 12.0) -> dict:
    """连接行情网关、鉴权、订阅并返回黄金9999的实时行情字典。"""
    headers = {"Origin": ORIGIN, "User-Agent": USER_AGENT}
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout

    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(WS_URL, headers=headers, heartbeat=None) as ws:
            await ws.send_bytes(_build_auth())
            subscribed = False
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise asyncio.TimeoutError("等待行情数据超时")
                msg = await asyncio.wait_for(ws.receive(), timeout=remaining)

                if msg.type == aiohttp.WSMsgType.BINARY:
                    authed, quote = _decode_message(msg.data)
                    if quote and quote.get("rt", {}).get("last") is not None:
                        return quote
                    if authed and not subscribed:
                        await ws.send_bytes(_build_subscribe())
                        subscribed = True
                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSING,
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.ERROR,
                ):
                    raise ConnectionError("行情连接已关闭")


# ---------------------------------------------------------------------------
# 文本格式化
# ---------------------------------------------------------------------------
def _fmt(v, suffix: str = "") -> str:
    return f"{v:.2f}{suffix}" if isinstance(v, (int, float)) else "—"


def format_quote(q: dict) -> str:
    rt = q.get("rt") or {}
    last = rt.get("last")
    updown = rt.get("updown") or 0.0
    rate = rt.get("updown_rate")
    bid = (rt.get("bid") or [None])[0]
    ask = (rt.get("ask") or [None])[0]

    if updown > 0:
        mark, sign = "🔴", "+"
    elif updown < 0:
        mark, sign = "🟢", ""
    else:
        mark, sign = "⚪", ""

    lines = [
        f"📊 {GOLD_NAME} 实时行情",
        f"最新价：{_fmt(last)} 元/克 {mark}",
        f"涨跌：{sign}{_fmt(updown)}（{sign}{_fmt(rate, '%')}）",
        f"今开：{_fmt(q.get('open'))}　昨收：{_fmt(q.get('pre_close'))}",
        f"最高：{_fmt(q.get('high'))}　最低：{_fmt(q.get('low'))}",
        f"买价：{_fmt(bid)}　卖价：{_fmt(ask)}",
        f"更新：{time.strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 插件主体
# ---------------------------------------------------------------------------
@register(
    "astrbot_plugin_goldprice",
    "githubcjx",
    "查询黄金9999（Au99.99）实时金价并返回群聊，支持自定义触发指令与生效群聊",
    "1.0.0",
)
class GoldPricePlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.config = config

    async def initialize(self):
        # Blowfish 自检：保证本机加密实现与行情网关一致。
        try:
            cipher = Blowfish.new(AUTH_KEY, Blowfish.MODE_CBC, AUTH_IV)
            ct = cipher.encrypt(pad(_SELFTEST_PLAINTEXT, Blowfish.block_size))
            if ct.hex() != _SELFTEST_CIPHER_HEX:
                logger.error(
                    "[goldprice] Blowfish 自检未通过，加密结果与预期不符，鉴权可能失败。"
                )
            else:
                logger.info("[goldprice] 插件已加载，Blowfish 自检通过。")
        except Exception:
            logger.exception("[goldprice] Blowfish 自检异常")

    def _matched(self, event: AstrMessageEvent) -> bool:
        triggers = [
            str(t).strip()
            for t in (self.config.get("triggers", ["/金价"]) or [])
            if str(t).strip()
        ] or ["/金价"]
        text = (event.message_str or "").strip()
        if text not in triggers:
            return False
        group_id = event.get_group_id()
        if group_id:  # 群聊：检查白名单
            enabled = [
                str(g).strip()
                for g in (self.config.get("enabled_groups", []) or [])
                if str(g).strip()
            ]
            if enabled and str(group_id) not in enabled:
                return False
        return True

    @filter.event_message_type(filter.EventMessageType.ALL)
    async def on_message(self, event: AstrMessageEvent):
        if not self._matched(event):
            return

        event.stop_event()  # 命中触发词，阻止该消息继续走 LLM 等后续流程
        try:
            quote = await fetch_gold_quote()
            yield event.plain_result(format_quote(quote))
        except asyncio.TimeoutError:
            logger.warning("[goldprice] 查询金价超时")
            yield event.plain_result("⚠️ 查询金价超时，请稍后再试。")
        except Exception as e:
            logger.exception("[goldprice] 查询金价失败")
            yield event.plain_result(f"⚠️ 查询金价失败：{e}")

    async def terminate(self):
        pass
