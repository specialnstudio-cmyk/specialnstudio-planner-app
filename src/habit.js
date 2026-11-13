// Habit tracker ("Günlük Takip", static files in /takip/): reminders by Web Push.
//
// The app keeps its data on the phone. It sends here only what a reminder needs: the push subscription, the time zone,
// the day's reminder slots (time, text, which check-ins each covers) and which check-ins are already answered.
// Each phone gets its own Habit Durable Object (named by a random id the phone made up), which holds that record and its
// own VAPID key pair, and wakes itself with an alarm at the next slot. A slot whose check-ins are all answered is skipped.
import { DurableObject } from "cloudflare:workers";

const API = "/takip/api/";
const CONTACT = "https://specialnstudio-planner.specialnstudio.workers.dev/takip/";  // VAPID "sub"
const MAX_SLOTS = 24;

export async function habitApi(req, env, url) {
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
                   items: (Array.isArray(x.items) ? x.items : []).slice(0, 20).map(i => String(i).slice(0, 60)) }))
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

function minutes(t) { return +t.slice(0, 2) * 60 + +t.slice(3); }
