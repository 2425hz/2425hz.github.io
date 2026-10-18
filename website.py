"""
Roblox Community - login website.

What it does:
  1. Opens when someone clicks "Log in with Roblox" in Discord.
  2. Sends them to Roblox to press Allow.
  3. Roblox sends them back here (/callback). We read their Roblox user ID.
  4. The bot (running on BisectHosting) asks this site every few seconds
     "anyone finished?" and links the accounts itself.

Environment variables (set these on the host, never in this file):
  ROBLOX_CLIENT_ID      from the Roblox OAuth app page
  ROBLOX_CLIENT_SECRET  from the Roblox OAuth app page
  SHARED_SECRET         a long random text, SAME value in the bot's settings
  PUBLIC_URL            this site's address, e.g. https://roblox-login.onrender.com
  PRIVACY_URL           (optional) link to your privacy policy
  TERMS_URL             (optional) link to your terms of service
  PORT                  most hosts set this for you

Start command: python website.py
"""

import base64
import hashlib
import hmac
import html
import json
import os
import time
from urllib.parse import urlencode

import aiohttp
from aiohttp import web

CLIENT_ID = os.getenv("ROBLOX_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("ROBLOX_CLIENT_SECRET", "")
SHARED_SECRET = os.getenv("SHARED_SECRET", "")
PUBLIC_URL = os.getenv("PUBLIC_URL", "").rstrip("/")
PRIVACY_URL = os.getenv("PRIVACY_URL", "")
TERMS_URL = os.getenv("TERMS_URL", "")
PORT = int(os.getenv("PORT", "8080"))

if not (CLIENT_ID and CLIENT_SECRET and SHARED_SECRET and PUBLIC_URL):
    raise SystemExit(
        "Set ROBLOX_CLIENT_ID, ROBLOX_CLIENT_SECRET, SHARED_SECRET and PUBLIC_URL first."
    )

REDIRECT_URI = f"{PUBLIC_URL}/callback"
AUTH_URL = "https://apis.roblox.com/oauth/v1/authorize"
TOKEN_URL = "https://apis.roblox.com/oauth/v1/token"
USERINFO_URL = "https://apis.roblox.com/oauth/v1/userinfo"

COOKIE = "rbx_login"
KEEP_SECONDS = 3600

# Both live in memory. That is fine: entries only need to survive a few seconds.
results: dict = {}  # nonce -> finished login waiting for the bot
used_nonces: dict = {}  # nonce -> time, so one login link works only once


# ---------------------------------------------------------------------------
# Login link tokens (made by the bot, checked here)
# ---------------------------------------------------------------------------


def verify_token(token: str):
    """Returns the token data, or None if it is fake, expired or damaged."""
    try:
        body, sig = token.rsplit(".", 1)
        good = hmac.new(SHARED_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig.encode(), good.encode()):
            return None
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if float(data["e"]) < time.time():
            return None
        return data
    except Exception:
        return None


def cleanup() -> None:
    cutoff = time.time() - KEEP_SECONDS
    for key in [k for k, v in used_nonces.items() if v < cutoff]:
        used_nonces.pop(key, None)
    for key in [k for k, v in results.items() if v["at"] < cutoff]:
        results.pop(key, None)


def api_authorized(request: web.Request) -> bool:
    sent = request.headers.get("Authorization", "")
    return hmac.compare_digest(sent.encode(), f"Bearer {SHARED_SECRET}".encode())


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

STYLE = """
:root{--bg:#f5f7fb;--card:#fff;--text:#162033;--muted:#5b6678;--accent:#3b82f6;--ok:#1f9d57;--bad:#d64545;--line:#dfe5ef}
@media (prefers-color-scheme:dark){:root{--bg:#0f1624;--card:#172033;--text:#e8edf7;--muted:#9aa7bd;--accent:#6ea3f8;--ok:#43c47f;--bad:#ef7676;--line:#27324a}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:var(--bg);color:var(--text);
font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;line-height:1.55}
main{width:100%;max-width:440px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:32px 28px}
h1{margin:0 0 10px;font-size:1.5rem;line-height:1.25}
p{margin:0 0 14px;color:var(--muted)}
.mark{width:44px;height:6px;border-radius:3px;margin-bottom:22px;background:var(--accent)}
.ok .mark{background:var(--ok)}.bad .mark{background:var(--bad)}
footer{margin-top:22px;font-size:.85rem}
footer a{color:var(--accent);margin-right:14px}
"""


def page(title: str, body: str, kind: str = "", status: int = 200) -> web.Response:
    links = ""
    if PRIVACY_URL:
        links += f'<a href="{html.escape(PRIVACY_URL)}">Privacy Policy</a>'
    if TERMS_URL:
        links += f'<a href="{html.escape(TERMS_URL)}">Terms of Service</a>'
    footer = f"<footer>{links}</footer>" if links else ""
    text = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{STYLE}</style></head>"
        f'<body><main class="{kind}"><div class="mark"></div>'
        f"<h1>{html.escape(title)}</h1>{body}{footer}</main></body></html>"
    )
    return web.Response(text=text, content_type="text/html", status=status)


def fail(message: str, status: int = 400) -> web.Response:
    resp = page("Verification did not finish", f"<p>{html.escape(message)}</p>", "bad", status)
    resp.del_cookie(COOKIE)
    return resp


async def home(request: web.Request) -> web.Response:
    return page(
        "Roblox Community",
        "<p>This site confirms which Roblox account belongs to you. "
        "Start from Discord: press <b>Verify with Roblox</b> in a server that uses the bot.</p>"
        "<p>We only read your Roblox user ID. We never see your password and never change anything on your account.</p>",
    )


async def health(request: web.Request) -> web.Response:
    return web.Response(text="ok")


# ---------------------------------------------------------------------------
# Login flow
# ---------------------------------------------------------------------------


async def start(request: web.Request) -> web.Response:
    """The bot's link opens here. We remember the token in a cookie, then go to Roblox."""
    token = request.query.get("t", "")
    data = verify_token(token)
    if data is None:
        return fail("This login link is invalid or expired. Press the button in Discord again.")
    if data["n"] in used_nonces:
        return fail("This login link was already used. Press the button in Discord again.")

    params = urlencode(
        {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "response_type": "code",
            "state": token,
        }
    )
    resp = web.HTTPFound(f"{AUTH_URL}?{params}")
    resp.set_cookie(COOKIE, token, max_age=600, httponly=True, secure=True, samesite="Lax")
    return resp


async def callback(request: web.Request) -> web.Response:
    cleanup()
    if request.query.get("error"):
        return fail("The login was cancelled. Press the button in Discord to try again.")

    state = request.query.get("state", "")
    code = request.query.get("code", "")
    data = verify_token(state)
    cookie = request.cookies.get(COOKIE, "")

    # The cookie proves the same browser that opened the link is the one finishing it.
    if data is None or not code or not hmac.compare_digest(cookie.encode(), state.encode()):
        return fail("Open the login link from Discord again, in the same browser, and finish it there.")

    nonce = data["n"]
    if nonce in used_nonces:
        return fail("This login link was already used. Press the button in Discord again.")
    used_nonces[nonce] = time.time()

    session: aiohttp.ClientSession = request.app["session"]
    try:
        async with session.post(
            TOKEN_URL,
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
            },
        ) as resp:
            if resp.status != 200:
                return fail("Roblox did not accept the login. Please try again.")
            access_token = (await resp.json())["access_token"]

        async with session.get(
            USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"}
        ) as resp:
            if resp.status != 200:
                return fail("Could not read your Roblox account. Please try again.")
            roblox_id = int((await resp.json())["sub"])
    except (aiohttp.ClientError, KeyError, ValueError, TimeoutError):
        return fail("Could not reach Roblox. Please try again in a moment.", 502)

    results[nonce] = {
        "id": nonce,
        "discord_id": str(data["u"]),
        "guild_id": str(data["g"]) if data.get("g") else "",
        "roblox_id": roblox_id,
        "at": time.time(),
    }

    resp = page(
        "You are verified",
        "<p>Your Roblox account is linked. You can close this tab and go back to Discord. "
        "Your nickname and role update within a few seconds.</p>",
        "ok",
    )
    resp.del_cookie(COOKIE)
    return resp


# ---------------------------------------------------------------------------
# API used by the bot only (needs SHARED_SECRET)
# ---------------------------------------------------------------------------


async def api_pending(request: web.Request) -> web.Response:
    if not api_authorized(request):
        return web.json_response({"error": "unauthorized"}, status=401)
    cleanup()
    return web.json_response({"results": list(results.values())})


async def api_ack(request: web.Request) -> web.Response:
    if not api_authorized(request):
        return web.json_response({"error": "unauthorized"}, status=401)
    try:
        ids = (await request.json()).get("ids", [])
    except Exception:
        return web.json_response({"error": "bad request"}, status=400)
    for item in ids:
        results.pop(str(item), None)
    return web.json_response({"ok": True})


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


async def on_startup(app: web.Application) -> None:
    app["session"] = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15))


async def on_cleanup(app: web.Application) -> None:
    await app["session"].close()


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", home)
    app.router.add_get("/health", health)
    app.router.add_get("/start", start)
    app.router.add_get("/callback", callback)
    app.router.add_get("/api/pending", api_pending)
    app.router.add_post("/api/ack", api_ack)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


if __name__ == "__main__":
    web.run_app(build_app(), host="0.0.0.0", port=PORT)
