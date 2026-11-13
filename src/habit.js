// Habit tracker ("Günlük Takip", static files in /takip/): reminders by Web Push.
//
// The app keeps its data on the phone. It sends here only what a reminder needs: the push subscription, the time zone,
// the day's reminder slots (time, text, which check-ins each covers) and which check-ins are already answered.
// The app opens only with an access code (see habit()).
// Each phone gets its own Habit Durable Object (named by a random id the phone made up), which holds that record and its
// own VAPID key pair, and wakes itself with an alarm at the next slot. A slot whose check-ins are all answered is skipped.
import { DurableObject } from "cloudflare:workers";

import { CODES } from "./habit_codes.js";

const ROOT = "/takip/";
const API = "/takip/api/";
const CONTACT = "https://specialnstudio-planner.specialnstudio.workers.dev/takip/";  // VAPID "sub"
const MAX_SLOTS = 24;
const OPEN_FILES = /^\/takip\/(manifest\.webmanifest|icon-512\.png|zebra\.svg|sun\.svg)$/;  // the home-screen icon and the login page's art
const MAX_DEVICES = 3;  // browsers one access code can open (on an iPhone, Safari and the home-screen app count as two)
const COOKIE_DAYS = 3 * 365;

// Everything under /takip/ opens only for a browser holding a cookie made from one of the access codes in habit_codes.js.
export async function habit(req, env, url) {
  if (url.pathname === "/takip") return Response.redirect(url.origin + ROOT, 301);
  if (OPEN_FILES.test(url.pathname)) return env.ASSETS.fetch(req);
  if (url.pathname === ROOT + "__giris") return req.method === "POST" ? login(req, env) : Response.redirect(url.origin + ROOT, 303);
  if (!(await allowed(req, env))) {
    if (url.pathname === ROOT || url.pathname === ROOT + "index.html") return loginPage("", 403);
    return json({ error: "locked" }, 401);
  }
  return url.pathname.startsWith(API) ? habitApi(req, env, url) : env.ASSETS.fetch(req);
}

async function sha(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(d), x => x.toString(16).padStart(2, "0")).join("");
}

async function sign(env, text) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.COOKIE_SECRET || "takip"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("takip|" + text)));
}

async function allowed(req, env) {
  const m = (req.headers.get("cookie") || "").match(/(?:^|;\s*)tk=([a-f0-9]{64})\.([a-f0-9]{16})\.([\w-]+)/);
  return !!m && CODES.has(m[1]) && m[3] === await sign(env, m[1] + "|" + m[2]);
}

async function login(req, env) {
  const form = await req.formData();
  const shown = String(form.get("sifre") || "").slice(0, 40);
  const hash = await sha(shown.toUpperCase().replace(/[^A-Z0-9]/g, ""));
  if (!CODES.has(hash)) return loginPage("wrong", 403, shown);
  const dev = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
  if (!(await env.HABIT.get(env.HABIT.idFromName("codes")).claim(hash, dev))) return loginPage("limit", 403, shown);
  const cookie = `tk=${hash}.${dev}.${await sign(env, hash + "|" + dev)}; Path=${ROOT}; Max-Age=${COOKIE_DAYS * 86400}; HttpOnly; Secure; SameSite=Lax`;
  return new Response(null, { status: 303, headers: { location: ROOT, "set-cookie": cookie, "cache-control": "no-store" } });
}

function loginPage(err, status, shown = "") {
  const msg = { wrong: "Bu şifre tanınmadı. Harfleri ve rakamları kontrol edip yeniden dene.",
                limit: `Bu şifre zaten ${MAX_DEVICES} cihazda açılmış. Yardım için bize yaz.` }[err] || "";
  const esc = s => s.replace(/[&<>"']/g, c => "&#" + c.charCodeAt(0) + ";");
  return new Response(`<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="robots" content="noindex, nofollow">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="Günlük Takip"><meta name="theme-color" content="#2348C8">
<link rel="manifest" href="manifest.webmanifest"><link rel="apple-touch-icon" href="icon-512.png"><title>Günlük Takip</title>
<link href="https://fonts.googleapis.com/css2?family=Big+Shoulders+Display:wght@900&family=Caveat+Brush&family=Space+Grotesk:wght@400;700&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box}html,body{margin:0;min-height:100%}
body{min-height:100vh;min-height:100dvh;background:#2348C8 url(zebra.svg) center/cover;font-family:'Space Grotesk',system-ui,sans-serif;color:#2A1630;
  display:flex;align-items:center;justify-content:center;padding:20px}
form{width:100%;max-width:400px;background:#FFC93C;border:3px solid #2A1630;border-radius:22px;box-shadow:6px 6px 0 #2A1630;padding:20px 18px 22px;text-align:center}
img{width:110px;height:110px;background:#FFF6E9;border:3px solid #2A1630;border-radius:50%}
h1{font-family:'Big Shoulders Display',sans-serif;font-weight:900;text-transform:uppercase;font-size:46px;line-height:.9;margin:10px 0 4px}
p{margin:0 0 14px;font-size:15px}.h{font-family:'Caveat Brush',cursive;font-size:22px;color:#E0177E}
input{width:100%;border:3px solid #2A1630;border-radius:14px;padding:14px 10px;font:700 22px 'Space Grotesk',monospace;text-align:center;letter-spacing:.08em;text-transform:uppercase;background:#fff;color:#2A1630}
button{width:100%;margin-top:12px;min-height:56px;border:3px solid #2A1630;border-radius:16px;background:#FF3E8A;color:#fff;font:700 18px 'Space Grotesk',sans-serif;box-shadow:4px 4px 0 #2A1630}
.s{display:inline-block;margin-top:16px;padding:7px 14px;border-radius:999px;background:#2A1630;color:#FFF6E9;font-size:13px;font-weight:700;letter-spacing:.14em;text-decoration:none}
.e{background:#fff;border:3px solid #2A1630;border-radius:12px;padding:10px;font-weight:700;font-size:14px}</style></head><body>
<form method="post" action="__giris"><img src="sun.svg" alt=""><h1>Günlük Takip</h1><p class="h">Her gün %100'e!</p>
${msg ? `<p class="e">${msg}</p>` : "<p>Başlamak için sana verilen şifreyi yaz.</p>"}
<input name="sifre" value="${esc(shown)}" placeholder="XXXXX-XXXXX" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="24" required aria-label="Şifre">
<button>Aç ⚡</button><a class="s" href="https://www.etsy.com/shop/SpecialNStudio?section_id=60970601" target="_blank" rel="noopener">SPECIALNSTUDIO</a></form></body></html>`, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}

async function habitApi(req, env, url) {
  const m = url.pathname.slice(API.length).match(/^([a-f0-9]{32})\/(key|sync|test)$/);
  if (!m || req.method !== "POST") return json({ error: "not found" }, 404);
  const stub = env.HABIT.get(env.HABIT.idFromName(m[1]));
  let body = {};
  try { body = await req.json(); } catch (e) { /* key and test need no body */ }
  try {
    if (m[2] === "key") return json({ key: await stub.publicKey() });
    if (m[2] === "sync") return json(await stub.sync(body));
    return json(await stub.test());
  } catch (e) {
    return json({ error: String(e).slice(0, 200) }, 500);
  }
}

function json(o, status = 200) {
  return new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

export class Habit extends DurableObject {
  // the object named "codes" keeps which browsers each access code has opened
  async claim(hash, dev) {
    const devs = (await this.ctx.storage.get("c:" + hash)) || [];
    if (devs.length >= MAX_DEVICES) return false;
    devs.push({ dev, at: Date.now() });
    await this.ctx.storage.put("c:" + hash, devs);
    return true;
  }

  async keys() {
    let k = await this.ctx.storage.get("vapid");
    if (!k) {
      const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
      k = { priv: await crypto.subtle.exportKey("jwk", pair.privateKey), pub: b64(await crypto.subtle.exportKey("raw", pair.publicKey)) };
      await this.ctx.storage.put("vapid", k);
    }
    return k;
  }

  async publicKey() { return (await this.keys()).pub; }

  async sync(b) {
    const s = this.ctx.storage;
    const rec = (await s.get("rec")) || { sent: { date: "", ids: [] } };
    const sub = b.sub && typeof b.sub.endpoint === "string" && /^https:\/\//.test(b.sub.endpoint) && b.sub.keys &&
      b.sub.keys.p256dh && b.sub.keys.auth ? { endpoint: b.sub.endpoint.slice(0, 1000), keys: { p256dh: String(b.sub.keys.p256dh), auth: String(b.sub.keys.auth) } } : null;
    rec.sub = sub;
    rec.tz = validTz(b.tz) ? b.tz : "Europe/Istanbul";
    rec.slots = (Array.isArray(b.slots) ? b.slots : []).slice(0, MAX_SLOTS)
      .filter(x => x && /^\d\d:\d\d$/.test(x.time))
      .map(x => ({ time: x.time, title: String(x.title || "").slice(0, 80), body: String(x.body || "").slice(0, 200),
                   items: (Array.isArray(x.items) ? x.items : []).slice(0, 20).map(i => String(i).slice(0, 60)),
                   // a slot that comes round only every N days, counted from a start date (the report reminder)
                   every: Math.min(Math.max(parseInt(x.every) || 1, 1), 60), from: /^\d{4}-\d\d-\d\d$/.test(x.from) ? x.from : "" }))
      .sort((a, b2) => a.time < b2.time ? -1 : 1);
    rec.answered = { date: String((b.answered && b.answered.date) || "").slice(0, 10),
                     ids: ((b.answered && Array.isArray(b.answered.ids)) ? b.answered.ids : []).slice(0, 200).map(String) };
    await s.put("rec", rec);
    await this.schedule(rec);
    return { ok: true, push: !!sub };
  }

  async test() {
    const rec = await this.ctx.storage.get("rec");
    if (!rec || !rec.sub) return { ok: false, reason: "nosub" };
    const status = await this.push(rec.sub, { title: "Bildirimler açık ⚡", body: "Gün içinde böyle haber vereceğim. Hadi %100'e!", tag: "test" });
    return { ok: status >= 200 && status < 300, status };
  }

  async alarm() {
    const s = this.ctx.storage;
    const rec = await s.get("rec");
    if (!rec || !rec.sub) return;
    const now = localNow(rec.tz);
    if (rec.sent.date !== now.date) rec.sent = { date: now.date, ids: [] };
    const answered = rec.answered.date === now.date ? rec.answered.ids : [];
    for (const slot of rec.slots) {
      if (slot.time > now.time || rec.sent.ids.includes(slot.time)) continue;
      rec.sent.ids.push(slot.time);
      // only a slot that just came due is announced (not one from hours ago), and only if something in it is still open
      if (minutes(now.time) - minutes(slot.time) > 20 || slot.items.every(i => answered.includes(i))) continue;
      if (slot.every > 1 && (!slot.from || days(slot.from, now.date) < 1 || days(slot.from, now.date) % slot.every)) continue;
      const status = await this.push(rec.sub, { title: slot.title, body: slot.body, tag: "slot-" + slot.time });
      if (status === 404 || status === 410) { rec.sub = null; break; }  // the phone dropped the subscription
    }
    await s.put("rec", rec);
    await this.schedule(rec);
  }

  async schedule(rec) {
    await this.ctx.storage.deleteAlarm();
    if (!rec.sub || !rec.slots.length) return;
    const now = localNow(rec.tz);
    const sent = rec.sent.date === now.date ? rec.sent.ids : [];
    const next = rec.slots.find(x => !sent.includes(x.time) && minutes(x.time) >= minutes(now.time) - 20);
    let wait = next ? minutes(next.time) - minutes(now.time) : 24 * 60 - minutes(now.time) + minutes(rec.slots[0].time);
    if (next && wait <= 0) wait = 0;
    // minutes to the slot, counted on the local clock (a daylight-saving night can shift one reminder by an hour)
    await this.ctx.storage.setAlarm(Date.now() + Math.max(wait * 60000 - now.sec * 1000, 2000));
  }

  // ---------- Web Push (RFC 8291 aes128gcm, RFC 8292 VAPID) ----------
  async push(sub, payload) {
    const k = await this.keys();
    const body = await encrypt(sub, new TextEncoder().encode(JSON.stringify(payload)));
    const aud = new URL(sub.endpoint).origin;
    const head = b64(new TextEncoder().encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
    const claims = b64(new TextEncoder().encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: CONTACT })));
    const key = await crypto.subtle.importKey("jwk", k.priv, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(`${head}.${claims}`));
    let r;
    try {
      r = await fetch(sub.endpoint, {
        method: "POST", body,
        headers: { "content-encoding": "aes128gcm", "content-type": "application/octet-stream", ttl: "3600", urgency: "high",
                   authorization: `vapid t=${head}.${claims}.${b64(sig)}, k=${k.pub}` },
      });
    } catch (e) {
      return 0;  // push service unreachable: skip this one, the next slot tries again
    }
    return r.status;
  }
}

export async function encrypt(sub, plain) {
  const ua = unb64(sub.keys.p256dh), auth = unb64(sub.keys.auth);
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const as = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", ua, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const secret = await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, eph.privateKey, 256);
  const ikm = await hkdf(auth, secret, cat(new TextEncoder().encode("WebPush: info\0"), ua, as), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, new TextEncoder().encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, new TextEncoder().encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, cat(plain, new Uint8Array([2]))));
  return cat(salt, new Uint8Array([0, 0, 16, 0, as.length]), as, ct);
}

async function hkdf(salt, ikm, info, len) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, len * 8));
}

function cat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function b64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64(s) {
  return Uint8Array.from(atob(String(s).replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}

function validTz(tz) {
  try { new Intl.DateTimeFormat("en", { timeZone: tz }); return typeof tz === "string"; } catch (e) { return false; }
}

function localNow(tz) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }).formatToParts(new Date()).map(x => [x.type, x.value]));
  return { date: `${p.year}-${p.month}-${p.day}`, time: `${p.hour}:${p.minute}`, sec: +p.second };
}

function days(a, b) { return Math.round((Date.parse(b) - Date.parse(a)) / 86400000); }

function minutes(t) { return +t.slice(0, 2) * 60 + +t.slice(3); }
