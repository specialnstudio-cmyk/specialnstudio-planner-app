// Planner apps with order-number activation.
//
// Static files are served from the repo (assets). Apps listed in PRODUCTS open only for a browser that holds an
// activation cookie; to get one the buyer types their Etsy order number, which is looked up with the Etsy API
// (the receipt must contain one of the app's listings). Each order can activate MAX_DEVICES browsers.
// Every app folder is protected; one without a listing in PRODUCTS cannot be activated yet.
//
// Secrets (set by the "Planlayıcı uygulama koruması" workflow in specialnstudio1): ETSY_API_KEY, ETSY_SHARED_SECRET,
// COOKIE_SECRET, ADMIN_SECRET. The Etsy login itself (rotating refresh token) lives in the Gate Durable Object,
// so only one place ever refreshes it.
import { DurableObject } from "cloudflare:workers";
import { habitApi, Habit } from "./habit.js";

export { Habit };

const BASE = "/p/a4c9eafbf1/";
// Every app folder under BASE is protected. An app opens with an order of one of its listings;
// an app with no listing yet cannot be activated (add its listing id here when the listing goes up).
const PRODUCTS = {  // app folder → Etsy listing ids that unlock it
  "plum-en-mon": ["4611085973"],
  "plum-en-sun": ["4611085973"],
  "plum-tr-mon": ["4611105908"],
  "energy-en-mon": ["4611256878"], "energy-en-sun": ["4611256878"],
  "energy-tr-mon": ["4611219123"], "energy-tr-sun": ["4611219123"],
  "leopard-en-mon": ["4611242342"], "leopard-en-sun": ["4611242342"],
  "leopard-tr-mon": ["4611226131"], "leopard-tr-sun": ["4611226131"],
  "poppy-en-mon": ["4611247886"], "poppy-en-sun": ["4611247886"],
  "zebra-en-mon": ["4611250640"], "zebra-en-sun": ["4611250640"],
  // the Zebra TR PDF planner (4602313474) also unlocks the app, as its bonus
  "zebra-tr-mon": ["4611253704", "4602313474"], "zebra-tr-sun": ["4611253704", "4602313474"],
};
const OPEN_FILES = /\/(manifest\.webmanifest|icon-512\.png|sw\.js|fonts\/[^/]+\.ttf)$/;  // fetched without cookies, or by the activation page
const MAX_DEVICES = 5;
const COOKIE_DAYS = 3 * 365;
const ETSY_API = "https://openapi.etsy.com/v3/application";
const ETSY_TOKEN = "https://api.etsy.com/v3/public/oauth/token";

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname.startsWith("/__admin/")) return admin(req, env, url);
    if (url.pathname.startsWith("/takip/api/")) return habitApi(req, env, url);
    const m = url.pathname.startsWith(BASE) && url.pathname.slice(BASE.length).match(/^([a-z0-9-]+)(\/.*)?$/);
    const app = m && m[1];
    if (!app || OPEN_FILES.test(url.pathname)) return env.ASSETS.fetch(req);
    const rest = m[2] || "";
    if (!env.COOKIE_SECRET) return new Response("Planner is being set up. Please try again later.", { status: 503, headers: { "cache-control": "no-store" } });
    if (rest === "") return Response.redirect(`${url.origin}${BASE}${app}/${url.search}${url.hash}`, 301);
    if (rest === "/__activate" && req.method === "POST") return activate(req, env, app);
    if (rest === "/__activate") return Response.redirect(`${url.origin}${BASE}${app}/`, 303);
    if (await allowed(req, env, app)) return env.ASSETS.fetch(req);
    if (rest === "/" || rest === "/index.html") return page(app, "", 403);
    return new Response("Not activated", { status: 403, headers: { "cache-control": "no-store" } });
  },
  async scheduled(_ev, env) {  // keeps the Etsy login alive (Etsy drops a login unused for 90 days)
    await gate(env).refreshIfOlder(20 * 3600);
  },
};

// ---------- cookies ----------
async function hmac(env, text) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.COOKIE_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function allowed(req, env, app) {
  const jar = Object.fromEntries((req.headers.get("cookie") || "").split(/;\s*/).filter(Boolean).map(c => {
    const i = c.indexOf("="); return [c.slice(0, i), c.slice(i + 1)];
  }));
  for (const listing of PRODUCTS[app] || []) {
    const v = jar["pl_" + listing];
    if (!v) continue;
    const [rid, dev, sig] = v.split(".");
    if (rid && dev && sig && sig === await hmac(env, `${listing}|${rid}|${dev}`)) return true;
  }
  return false;
}

// ---------- activation ----------
async function activate(req, env, app) {
  const form = await req.formData();
  const order = String(form.get("order") || "").replace(/[^0-9]/g, "");
  if (order.length < 6 || order.length > 14) return page(app, "format", 400);
  if (!(PRODUCTS[app] || []).length) return page(app, "other", 403, order);
  const dev = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
  const res = await gate(env).verify(order, PRODUCTS[app], dev);
  if (!res.ok) return page(app, res.reason, 403, order);
  const listing = res.listing;
  const cookie = `pl_${listing}=${order}.${dev}.${await hmac(env, `${listing}|${order}|${dev}`)}; Path=${BASE}; ` +
    `Max-Age=${COOKIE_DAYS * 86400}; HttpOnly; Secure; SameSite=Lax`;
  return new Response(null, { status: 303, headers: { location: `${BASE}${app}/`, "set-cookie": cookie, "cache-control": "no-store" } });
}

function gate(env) {
  return env.GATE.get(env.GATE.idFromName("main"));
}

// ---------- the Durable Object: Etsy login + activations ----------
export class Gate extends DurableObject {
  async verify(order, listings, dev) {
    const s = this.ctx.storage;
    let rec = await s.get("r:" + order);
    if (!rec) {
      let found;
      try {
        found = await this.receiptListings(order);
      } catch (e) {
        // Etsy unreachable or our login broken: let the buyer in and keep a note to review.
        await s.put("u:" + order, { at: Date.now(), err: String(e).slice(0, 200), listings });
        found = { listings: [listings[0]], unverified: true };
      }
      if (found === null) return { ok: false, reason: "notfound" };
      if (found.unpaid) return { ok: false, reason: "unpaid" };
      rec = { listings: found.listings, devices: [], at: Date.now(), unverified: !!found.unverified };
    }
    const listing = listings.find(l => rec.listings.includes(l));
    if (!listing) return { ok: false, reason: "other" };
    if (!rec.devices.includes(dev)) {
      if (rec.devices.length >= MAX_DEVICES) return { ok: false, reason: "limit" };
      rec.devices.push(dev);
    }
    await s.put("r:" + order, rec);
    return { ok: true, listing };
  }

  // null: no such order in this shop; {listings, unpaid}: what it bought. Throws on Etsy/login trouble.
  async receiptListings(order) {
    const tok = await this.access();
    const shop = await this.shopId(tok);
    const r = await fetch(`${this.env.ETSY_API_BASE || ETSY_API}/shops/${shop}/receipts/${order}`, { headers: this.headers(tok) });
    if (r.status === 404 || r.status === 400) return null;
    if (!r.ok) throw new Error(`receipt ${r.status} ${(await r.text()).slice(0, 120)}`);
    const j = await r.json();
    return { listings: (j.transactions || []).map(t => String(t.listing_id)), unpaid: j.is_paid === false };
  }

  headers(tok) {
    return { "x-api-key": `${this.env.ETSY_API_KEY}:${this.env.ETSY_SHARED_SECRET}`, authorization: `Bearer ${tok.access_token}` };
  }

  async shopId(tok) {
    let id = await this.ctx.storage.get("shop");
    if (id) return id;
    const uid = tok.access_token.split(".")[0];
    const r = await fetch(`${this.env.ETSY_API_BASE || ETSY_API}/users/${uid}/shops`, { headers: this.headers(tok) });
    if (!r.ok) throw new Error(`shops ${r.status}`);
    const j = await r.json();
    id = j.shop_id || (j.results && j.results[0] && j.results[0].shop_id);
    if (!id) throw new Error("no shop");
    await this.ctx.storage.put("shop", id);
    return id;
  }

  async access() {
    const tok = await this.ctx.storage.get("token");
    if (!tok) throw new Error("no etsy login");
    if (tok.expires_at > Date.now() / 1000 + 60) return tok;
    return this.refresh(tok);
  }

  async refresh(tok) {
    const r = await fetch(this.env.ETSY_TOKEN_URL || ETSY_TOKEN, {
      method: "POST",
      body: new URLSearchParams({ grant_type: "refresh_token", client_id: this.env.ETSY_API_KEY, refresh_token: tok.refresh_token }),
    });
    if (!r.ok) throw new Error(`refresh ${r.status} ${(await r.text()).slice(0, 120)}`);
    const j = await r.json();
    const now = Date.now() / 1000;
    const next = { access_token: j.access_token, refresh_token: j.refresh_token, expires_at: now + (j.expires_in || 3600) - 60, refreshed_at: now };
    await this.ctx.storage.put("token", next);  // Etsy replaces the refresh token on every use
    return next;
  }

  async refreshIfOlder(seconds) {
    const tok = await this.ctx.storage.get("token");
    if (tok && (Date.now() / 1000 - (tok.refreshed_at || 0)) > seconds) await this.refresh(tok);
  }

  async setToken(t) {
    await this.ctx.storage.put("token", { ...t, refreshed_at: Date.now() / 1000 });
    await this.ctx.storage.delete("shop");
  }

  async status() {
    const tok = await this.ctx.storage.get("token");
    const all = await this.ctx.storage.list();
    let orders = 0, devices = 0;
    const unverified = [];
    for (const [k, v] of all) {
      if (k.startsWith("r:")) { orders++; devices += v.devices.length; }
      if (k.startsWith("u:")) unverified.push({ order: k.slice(2), ...v });
    }
    let check = "ok";
    try { const t = await this.access(); await this.shopId(t); } catch (e) { check = String(e).slice(0, 200); }
    return { login: !!tok, refreshed_at: tok && tok.refreshed_at, etsy: check, orders, devices, unverified };
  }

  async grant(order, listings) {  // a test order for the shop owner: opens these listings without asking Etsy
    await this.ctx.storage.put("r:" + order, { listings: listings.map(String), devices: [], at: Date.now(), test: true });
  }

  async reset(order) {
    await this.ctx.storage.delete("r:" + order);
    await this.ctx.storage.delete("u:" + order);
  }
}

// ---------- admin (used by the GitHub workflow) ----------
async function admin(req, env, url) {
  const auth = req.headers.get("authorization") || "";
  if (!env.ADMIN_SECRET || auth !== `Bearer ${env.ADMIN_SECRET}`) return new Response("no", { status: 401 });
  const g = gate(env);
  if (url.pathname === "/__admin/token" && req.method === "POST") {
    const t = await req.json();
    await g.setToken({ access_token: t.access_token, refresh_token: t.refresh_token, expires_at: t.expires_at });
  } else if (url.pathname === "/__admin/grant" && req.method === "POST") {
    const b = await req.json();
    const order = String(b.order || "").replace(/[^0-9]/g, "");
    if (order.length < 6 || !Array.isArray(b.listings) || !b.listings.length) return new Response("bad", { status: 400 });
    await g.grant(order, b.listings);
  } else if (url.pathname === "/__admin/reset" && req.method === "POST") {
    await g.reset(String((await req.json()).order || ""));
  } else if (url.pathname !== "/__admin/status") return new Response("?", { status: 404 });
  return Response.json(await g.status());
}

// ---------- the activation page ----------
const T = {
  en: {
    title: "Activate your planner", lead: "Enter your Etsy order number once. Your planner then opens on this device.",
    label: "Etsy order number", ph: "e.g. 3456789012", btn: "Open my planner",
    help: "Find it on Etsy under You → Purchases and reviews, or in your order confirmation email (“Order #…”). " +
      "Each order can be used on up to 5 devices or browsers. On iPhone and iPad, after Add to Home Screen, enter it once more in the app.",
    err: {
      format: "That doesn't look like an order number. It has 9 to 11 digits.",
      notfound: "We couldn't find this order. Please check the number and try again.",
      other: "This order is for a different product. Please use the link from the guide that came with this order.",
      unpaid: "This order isn't paid yet. Please try again in a few minutes.",
      limit: "This order is already used on 5 devices. Please message the shop on Etsy and we'll reset it for you.",
    },
  },
  tr: {
    title: "Planlayıcını etkinleştir", lead: "Etsy sipariş numaranı bir kez yaz. Planlayıcın bu cihazda açılır.",
    label: "Etsy sipariş numarası", ph: "ör. 3456789012", btn: "Planlayıcımı aç",
    help: "Etsy'de Sen → Satın Alımlar ve Değerlendirmeler altında ya da sipariş onay e-postanda (“Sipariş no…”) bulursun. " +
      "Bir sipariş en fazla 5 cihazda ya da tarayıcıda kullanılabilir. iPhone ve iPad'de Ana Ekrana ekledikten sonra uygulamada bir kez daha yaz.",
    err: {
      format: "Bu bir sipariş numarasına benzemiyor. 9–11 haneden oluşur.",
      notfound: "Bu siparişi bulamadık. Numarayı kontrol edip tekrar dene.",
      other: "Bu sipariş başka bir ürüne ait. Lütfen bu siparişle gelen rehberdeki linki kullan.",
      unpaid: "Bu siparişin ödemesi henüz tamamlanmamış. Birkaç dakika sonra tekrar dene.",
      limit: "Bu sipariş 5 cihazda kullanılmış. Etsy'den mağazaya mesaj at, senin için sıfırlayalım.",
    },
  },
};

function esc(s) {
  return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
}

// The activation page wears the look of the app it opens (Plum Noir is the default).
const GF = '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Big+Shoulders+Display:wght@900&family=Caveat+Brush&family=Space+Grotesk:wght@400;700&family=DM+Serif+Display&display=swap">';
const FUN = (bg, title, font, btn, extra = "") => `${GF}<style>html,body{background:${bg}!important;font-family:"Space Grotesk",sans-serif!important}
.card{background:#FFF6E9!important;border:4px solid #2A1630!important;border-radius:28px!important;box-shadow:8px 8px 0 #2A1630!important}
h1{font-family:${font}!important;color:${title}!important;letter-spacing:.01em!important;font-size:40px!important;line-height:1!important}
label{font-family:"Space Grotesk",sans-serif!important;font-weight:700;color:#2A1630!important;letter-spacing:.08em!important}
input{border:3px solid #2A1630!important}
button{font-family:"Space Grotesk",sans-serif!important;font-weight:700;background:${btn}!important;color:#fff!important;border:3px solid #2A1630!important;box-shadow:4px 4px 0 #2A1630}
.help{color:#5A4560!important}${extra}</style>`;
const THEME = {
  energy: FUN("#FFAD68", "#FF5A36", '"Big Shoulders Display",sans-serif', "#FF3E8A", "h1{text-transform:uppercase;font-size:46px!important}"),
  leopard: FUN("#FFAD68", "#E8402A", '"DM Serif Display",serif', "#E8402A", "h1{text-transform:uppercase}"),
  zebra: FUN("#F7E3CF", "#E5508F", '"Caveat Brush",cursive', "#E5508F", "h1{text-transform:none!important;font-size:46px!important}"),
  poppy: FUN("#D2386C", "#8E003F", '"DM Serif Display",serif', "#EA582A", "h1{text-transform:uppercase}"),
};

function page(app, reason, status, order = "") {
  const L = T[app.split("-")[1] === "tr" ? "tr" : "en"];
  const err = reason ? `<p class="err">${esc(L.err[reason] || L.err.notfound)}</p>` : "";
  const html = `<!doctype html><html lang="${L === T.tr ? "tr" : "en"}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="robots" content="noindex">
<meta name="theme-color" content="#3A1A28"><link rel="manifest" href="manifest.webmanifest"><link rel="apple-touch-icon" href="icon-512.png">
<meta name="apple-mobile-web-app-capable" content="yes"><title>${esc(L.title)}</title>
<style>
@font-face{font-family:Italiana;src:url("fonts/Italiana-TR.ttf")}
@font-face{font-family:Crimson;src:url("fonts/CrimsonPro-Regular.ttf")}
html,body{margin:0;min-height:100%;background:#3A1A28;color:#3A1A28;font-family:Crimson,Georgia,serif}
body{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;box-sizing:border-box}
.card{background:#FAF5EE;max-width:420px;width:100%;padding:34px 28px 26px;border-radius:22px;border:2px solid #B08D57;box-shadow:0 20px 50px rgba(0,0,0,.35);box-sizing:border-box}
h1{font-family:Italiana,serif;font-weight:400;letter-spacing:.06em;text-transform:uppercase;font-size:28px;margin:0 0 8px}
.lead{font-size:18px;line-height:1.4;margin:0 0 20px}
label{display:block;font-family:Italiana,serif;letter-spacing:.14em;text-transform:uppercase;font-size:14px;color:#7A5A66;margin-bottom:6px}
input{width:100%;box-sizing:border-box;font:inherit;font-size:22px;padding:12px 14px;border:1.5px solid #B08D57;border-radius:12px;background:#fff;color:#3A1A28;-webkit-appearance:none}
input:focus{outline:none;border-color:#3A1A28;box-shadow:0 0 0 3px rgba(176,141,87,.3)}
button{margin-top:16px;width:100%;font-family:Italiana,serif;letter-spacing:.16em;text-transform:uppercase;font-size:17px;padding:14px;border:0;border-radius:99px;background:#3A1A28;color:#E7D3A8;cursor:pointer}
.help{font-size:14.5px;line-height:1.45;color:#7A5A66;margin:18px 0 0}
.err{background:#F6E3E6;border:1px solid #C77D93;color:#6B1F38;border-radius:10px;padding:10px 12px;font-size:16px;margin:0 0 14px}
</style>${THEME[app.split("-")[0]] || ""}</head><body><form class="card" method="post" action="__activate">
<h1>${esc(L.title)}</h1><p class="lead">${esc(L.lead)}</p>${err}
<label for="o">${esc(L.label)}</label><input id="o" name="order" inputmode="numeric" autocomplete="off" required placeholder="${esc(L.ph)}" value="${esc(order)}">
<button>${esc(L.btn)} ›</button><p class="help">${esc(L.help)}</p></form></body></html>`;
  return new Response(html, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}
