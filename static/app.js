// ---- Переключение тёмной/светлой темы ----
const root = document.documentElement;
document.getElementById('themeToggle').addEventListener('click', () => {
  const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  if (typeof setThemeCookie === 'function') setThemeCookie(next);
});

// ---- Выпадающее меню пользователя ----
const avatarBtn = document.getElementById('avatarBtn');
if (avatarBtn) {
  const dd = document.getElementById('userDropdown');
  avatarBtn.addEventListener('click', (e) => { e.stopPropagation(); dd.classList.toggle('open'); });
  document.addEventListener('click', () => dd.classList.remove('open'));
}

// ---- Синхронизация темы с cookie настроек ----
function getCookie(n){const m=document.cookie.match(new RegExp('(?:^|; )'+n+'=([^;]*)'));return m?decodeURIComponent(m[1]):null;}
function setThemeCookie(theme){
  let s = {};
  try { s = JSON.parse(getCookie('sgpt_settings')||'{}'); } catch(e){}
  if (Object.keys(s).length) {           // обновляем только если настройки уже сохраняли
    s.theme = theme;
    document.cookie = 'sgpt_settings=' + encodeURIComponent(JSON.stringify(s)) + ';max-age=31536000;path=/;samesite=Lax';
  }
}

// ---- Звук при появлении ответа ИИ (настройка «sound») ----
function playDing(){
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const o = ctx.createOscillator(), g = ctx.createGain();
    o.type = 'sine'; o.frequency.value = 880;
    g.gain.setValueAtTime(0.15, ctx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.6);
    o.connect(g); g.connect(ctx.destination);
    o.start(); o.stop(ctx.currentTime + 0.6);
  } catch(e){}
}
document.querySelectorAll('.ai-card[data-sound="1"]').forEach(() => playDing());

// ---- Кнопка «Очистить» в строке поиска на странице результатов ----
const topInput = document.querySelector('.searchbox-top input[name="search"]');
const clearTopBtn = document.getElementById('clearTopBtn');
if (topInput && clearTopBtn) {
  const upd = () => clearTopBtn.hidden = !topInput.value;
  topInput.addEventListener('input', upd); upd();
  clearTopBtn.addEventListener('click', () => { topInput.value=''; clearTopBtn.hidden=true; topInput.focus(); });
}
