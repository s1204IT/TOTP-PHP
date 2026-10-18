'use strict';
(() => {
  const popoverOpen = () => {
    try {
      return !!document.querySelector(':popover-open');
    } catch {
      return false;
    }
  };

  const wait = Number(document.body.dataset.refresh);
  if (wait > 0) {
    const due = Date.now() + wait * 1000;
    setInterval(() => {
      if (Date.now() >= due && !popoverOpen()) {
        location.assign(location.pathname);
      }
    }, 500);
  }

  document.querySelectorAll('[data-open]').forEach((el) => {
    if (el.showPopover) el.showPopover();
  });

  const toast = document.getElementById('toast');
  let hideTimer = 0;
  const hideToast = () => {
    if (toast) toast.classList.remove('show');
  };
  const say = (msg, ok) => {
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.toggle('bad', !ok);
    toast.classList.remove('show');
    void toast.offsetWidth;
    toast.classList.add('show');
    clearTimeout(hideTimer);
    hideTimer = setTimeout(hideToast, 1300);
  };
  document.addEventListener('pointerdown', (e) => {
    if (toast && toast.classList.contains('show') && !e.target.closest('[data-code]')) hideToast();
  }, true);

  const flashTimers = new WeakMap();
  const flash = (btn) => {
    btn.classList.add('copied');
    clearTimeout(flashTimers.get(btn));
    flashTimers.set(btn, setTimeout(() => btn.classList.remove('copied'), 800));
  };

  const legacyCopy = (text) => {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand('copy');
    } catch {}
    ta.remove();
    return ok;
  };
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-code]');
    if (!btn) return;
    e.preventDefault();
    const code = btn.dataset.code;
    let ok = false;
    try {
      await navigator.clipboard.writeText(code);
      ok = true;
    } catch {
      ok = legacyCopy(code);
    }
    if (ok) flash(btn);
    say(ok ? 'Copied!' : 'Can not copy.\nSorry.', ok);
  });
})();