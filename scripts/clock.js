// clock: control the time the page sees, for kits that only show the
// payload during the victim's business hours (client-side checks; a kit
// that checks its own server clock can only be met by scanning at the
// right time). The timezone stays the one matching the exit IP.
//
// settings.clock.mode:
//   "business-hours"  shift only if the local time (persona timezone) is
//                     outside `from`-`to` on `days`; then jump to the next
//                     allowed day at `at`
//   "fixed"           always set the local time to `at` (and `date`, if set)
//   "off"             leave the clock alone
//
// How: an init script wraps Date / Date.now in Proxies (toString stays
// native) and shifts performance.timeOrigin by the same offset, so Date and
// the performance clock agree. In-page, so observable in principle, and
// Workers keep the real time, hence opt-in. (Shifting the browser process
// clock with libfaketime was tried: unreliable inside the jail.)

// Wall-clock parts of `date` in `timeZone`.
function wall(date, timeZone) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", weekday: "short" })
    .formatToParts(date).map((x) => [x.type, x.value]));
  return { y: +p.year, mo: +p.month, d: +p.day, h: +p.hour, mi: +p.minute, s: +p.second, wd: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(p.weekday) };
}

// Page-side time shift (see header).
function shiftSource(offsetMs) {
  return `(() => {
    const off = ${Number(offsetMs)};
    const RealDate = Date, realNow = RealDate.now;
    const now = new Proxy(realNow, { apply: () => realNow() + off });
    const ShiftedDate = new Proxy(RealDate, {
      construct: (t, args, nt) => Reflect.construct(t, args.length ? args : [realNow() + off], nt),
      apply: (t) => new t(realNow() + off).toString(),
      get: (t, k, r) => (k === "now" ? now : Reflect.get(t, k, r)),
    });
    Object.defineProperty(RealDate.prototype, "constructor", { value: ShiftedDate, writable: true, enumerable: false, configurable: true });
    Object.defineProperty(globalThis, "Date", { value: ShiftedDate, writable: true, enumerable: false, configurable: true });
    const d = Object.getOwnPropertyDescriptor(Performance.prototype, "timeOrigin");
    if (d && d.get) Object.defineProperty(Performance.prototype, "timeOrigin", { ...d, get: new Proxy(d.get, { apply: (t, self) => Reflect.apply(t, self, []) + off }) });
  })();`;
}

const minutes = (hhmm) => { const [h, m] = hhmm.split(":").map(Number); return h * 60 + (m || 0); };

// Seconds to add to the real clock so the local time becomes the target.
function offsetSeconds(cfg, timeZone, now = new Date()) {
  const w = wall(now, timeZone);
  const nowWall = Date.UTC(w.y, w.mo - 1, w.d, w.h, w.mi, w.s);
  const nowMin = w.h * 60 + w.mi;
  const at = minutes(cfg.at);
  let target;
  if (cfg.mode === "fixed") {
    const [y, mo, d] = cfg.date ? cfg.date.split("-").map(Number) : [w.y, w.mo, w.d];
    target = Date.UTC(y, mo - 1, d, Math.floor(at / 60), at % 60, 0);
  } else if (cfg.mode === "business-hours") {
    if (cfg.days.includes(w.wd) && nowMin >= minutes(cfg.from) && nowMin < minutes(cfg.to)) return 0;
    let add = cfg.days.includes(w.wd) && nowMin < at ? 0 : 1; // today if before `at`, else the next allowed day
    while (!cfg.days.includes((w.wd + add) % 7)) add++;
    target = Date.UTC(w.y, w.mo - 1, w.d + add, Math.floor(at / 60), at % 60, 0);
  } else {
    return 0;
  }
  return Math.round((target - nowWall) / 1000);
}

module.exports = {
  name: "clock",

  settings: { clock: { mode: "business-hours", from: "09:00", to: "17:30", at: "10:15", days: [1, 2, 3, 4, 5], date: null } },

  ui: {
    "clock.mode": { options: ["business-hours", "fixed", "off"], help: "business-hours: jump to the next working day at `at` only if now is outside from-to; fixed: always `at`" },
    "clock.days": { help: "working days, 0 = Sunday" },
    "clock.date": { help: "fixed mode: YYYY-MM-DD (empty = today)" },
  },

  async page(ctx) {
    if (ctx.isPopup) return; // context-wide init script, added once
    const cfg = ctx.settings.clock;
    const tz = ctx.timezoneId || Intl.DateTimeFormat().resolvedOptions().timeZone;
    const offset = offsetSeconds(cfg, tz);
    if (!offset) return;
    ctx.log.clock = { mode: cfg.mode, timeZone: tz, offsetSeconds: offset, pageTime: new Date(Date.now() + offset * 1000).toISOString() };
    await ctx.context.addInitScript(shiftSource(offset * 1000));
  },

  offsetSeconds,
};
