(() => {
  const status = document.getElementById('copy-status');
  const toast = document.getElementById('toast');
  let toastTimer;

  const announce = (message) => {
    if (status) status.textContent = message;
    if (toast) {
      toast.textContent = message;
      toast.classList.add('is-visible');
      window.clearTimeout(toastTimer);
      toastTimer = window.setTimeout(() => toast.classList.remove('is-visible'), 2600);
    }
  };

  const fallbackCopy = (text) => {
    const previousFocus = document.activeElement;
    let field;
    try {
      field = document.createElement('textarea');
      field.value = text;
      field.setAttribute('readonly', '');
      field.setAttribute('aria-hidden', 'true');
      field.className = 'copy-helper';
      document.body.appendChild(field);
      field.focus({ preventScroll: true });
      field.select();
      return document.execCommand('copy');
    } catch (_) {
      return false;
    } finally {
      if (field) field.remove();
      try {
        if (previousFocus && typeof previousFocus.focus === 'function') previousFocus.focus({ preventScroll: true });
      } catch (_) { /* Focus restoration is best-effort. */ }
    }
  };

  document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      const value = button.getAttribute('data-copy');
      if (!value) return;
      let copied = false;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(value);
          copied = true;
        } else {
          copied = fallbackCopy(value);
        }
      } catch (_) {
        copied = fallbackCopy(value);
      }
      announce(copied ? '订阅地址已复制。使用前请先阅读安全须知。' : '复制失败，请使用“打开直链”或手动复制。');
    });
  });
})();
