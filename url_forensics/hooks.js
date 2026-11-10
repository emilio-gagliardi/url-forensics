(() => {
  const log = (kind, value) => { try { window.__forensics_log(kind, String(value).slice(0, 4096)); } catch (_) {} };
  const wrap = (obj, name, describe) => { try { const original = obj[name]; if (typeof original !== 'function') return; obj[name] = function(...args) { log(name, describe ? describe(args) : args[0]); return Reflect.apply(original, this, args); }; } catch (_) {} };
  wrap(navigator.clipboard, 'writeText');
  wrap(document, 'execCommand', a => a[0]);
  wrap(window, 'open');
  wrap(window, 'fetch', a => JSON.stringify({url: String(a[0]), body: a[1]?.body == null ? null : String(a[1].body)}));
  wrap(XMLHttpRequest.prototype, 'open', a => { this; return JSON.stringify({method:a[0],url:a[1]}); });
  wrap(XMLHttpRequest.prototype, 'send');
  wrap(window, 'atob'); wrap(window, 'eval'); wrap(window, 'Function', a => a.join('\n')); wrap(document, 'write', a => a.join(''));
  wrap(Location.prototype, 'assign'); wrap(Location.prototype, 'replace');
})();
