(function(){
  'use strict';

  // --- Helpers DOM ---
  const $ = sel => document.querySelector(sel);
  const $$ = sel => Array.from(document.querySelectorAll(sel));

  // --- Cookie helpers (no confíes en leer cookies httpOnly) ---
  function setCookie(name, value, days){
    const d = new Date(); d.setTime(d.getTime() + (days*24*60*60*1000));
    document.cookie = `${name}=${value};expires=${d.toUTCString()};path=/;SameSite=Lax`;
  }
  function deleteCookie(name){
    document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;SameSite=Lax`;
  }

  // helper para leer cookies (no funcionará para HttpOnly, pero útil para fallbacks)
  function getCookie(name) {
    try {
      const value = `; ${document.cookie}`;
      const parts = value.split(`; ${name}=`);
      if (parts.length === 2) return parts.pop().split(';').shift();
    } catch (e) {
      console.debug('getCookie error', e);
    }
    return null;
  }

  // --- Auth state ---
  let isAuthenticated = false;
  // No leer token desde localStorage por defecto: preferimos usar la cookie HttpOnly
  // enviada por el navegador. Mantener variable vacía evita enviar cabeceras
  // Authorization con tokens locales obsoletos que provocan 401s.
  let jwtToken = '';

  function getAuthHeaders(){
    const headers = {};
    const apiKey = ($('#apiKey') && $('#apiKey').value.trim()) || '';
    // If a cookie admin_jwt exists (HttpOnly in normal flow), prefer cookie-based
    // auth and do NOT send an Authorization header. This avoids sending stale
    // tokens from localStorage which can produce 401 responses despite the
    // cookie being valid (the backend will accept the cookie).
    try {
      const cookieAdmin = getCookie('admin_jwt');
      if (cookieAdmin) return headers;
    } catch (e) {
      // ignore
    }
    if (jwtToken) headers['Authorization'] = 'Bearer ' + jwtToken;
    else if (apiKey) headers['Authorization'] = 'Bearer ' + apiKey;
    return headers;
  }

  // --- Generic fetch helper: credentials included by default ---
  async function fetchWithRetry(url, opts = {}, retries = 1, delayMs = 700){
    const defaultOpts = { credentials: 'include', cache: 'no-store' };
    const merged = Object.assign({}, defaultOpts, opts);
    const raw = Object.assign({}, merged.headers || {}, merged._rawHeaders || {});
    merged.headers = raw;

    try{
      const res = await fetch(url, merged);
      if (!res.ok && res.status >= 500 && retries > 0){
        await new Promise(r => setTimeout(r, delayMs));
        return fetchWithRetry(url, opts, retries - 1, delayMs * 1.5);
      }
      // If we received 401 and we had sent an Authorization header, retry once
      // removing Authorization so the browser can use cookie-based auth instead.
      if (res.status === 401 && merged.headers && (merged.headers.Authorization || merged.headers.authorization)){
        if (retries > 0){
          // remove Authorization and retry once
          const newOpts = Object.assign({}, opts);
          const h = Object.assign({}, (newOpts.headers || {}), (newOpts._rawHeaders || {}));
          delete h.Authorization; delete h.authorization;
          newOpts._rawHeaders = h;
          await new Promise(r => setTimeout(r, 120));
          return fetchWithRetry(url, newOpts, retries - 1, delayMs);
        }
      }
      return res;
    }catch(err){
      if (retries > 0){
        await new Promise(r => setTimeout(r, delayMs));
        return fetchWithRetry(url, opts, retries - 1, delayMs * 1.5);
      }
      throw err;
    }
  }


  // --- UI helpers ---
  function escapeHtml(unsafe){
    return ('' + (unsafe || '')).replace(/[&<>"']/g, function(m){
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m];
    });
  }

  function updateAuthUI(){
    const accessCard = $('#accessCard');
    if (accessCard) accessCard.style.display = isAuthenticated ? 'none' : 'block';
    const btnLogin = $('#btnLogin');
    const btnRegister = $('#btnRegister');
    const btnLogout = $('#btnLogout');
    const divLogout = $('#logoutWrapper');
    if (btnLogin) btnLogin.style.display = isAuthenticated ? 'none' : 'inline-block';
    if (btnRegister) btnRegister.style.display = isAuthenticated ? 'none' : 'inline-block';
    if (divLogout) divLogout.style.display = isAuthenticated ? 'inline-block' : 'none';
    if (btnLogout) btnLogout.style.display = isAuthenticated ? 'inline-block' : 'none';

    $$('.auth-required').forEach(el => {
      if (isAuthenticated){
        el.classList.remove('auth-required');
        el.style.opacity = '1';
        el.style.pointerEvents = 'auto';
      } else {
        el.classList.add('auth-required');
        el.style.opacity = '0.5';
        el.style.pointerEvents = 'none';
      }
    });

    const status = $('#authStatus');
    if (status) status.textContent = isAuthenticated ? 'Autenticado' : 'No autenticado';
  }

    // --- Token refresh (if backend supports it) ---
    async function refreshToken() {
        try {
            const res = await fetchWithRetry('/api/v1/auth/refresh', {
                method: 'POST',
                credentials: 'include',
                retries: 1
            });
            
            if (res.ok) {
                const data = await res.json();
                if (data.token) {
                    jwtToken = data.token;
                    localStorage.setItem('admin_jwt', data.token);
                    setCookie('admin_jwt', data.token, 1);
                    return true;
                }
            }
        } catch (err) {
            console.debug('[refreshToken] Error:', err);
        }

        return false;
    }

    // --- Try auth check once (used internally) ---
  // Verifica sesión de forma ligera consultando el endpoint /auth/status que usa la cookie HttpOnly
  async function tryAuthCheck() {
    try {
      const res = await fetchWithRetry('/api/v1/auth/status', {
        method: 'GET',
        // credentials incluido por defecto en fetchWithRetry
        retries: 1,
        delayMs: 500
      });

      return res.ok;
    } catch (err) {
      console.debug('[tryAuthCheck] Error:', err);
      return false;
    }
  }

  // --- Core logic: check auth by asking backend (sends cookie httpOnly) ---
  async function checkAuth(){
    const redirectIfNot = true;

    // Intentamos una verificación ligera basada en cookie HttpOnly
    try {
      let ok = await tryAuthCheck();
      console.log('Resultado inicial de verificación de auth:', ok);

      // Si falla, intentamos refrescar token (si el backend soporta refresh) y reintentamos
      if (!ok) {
        const refreshed = await refreshToken();
        if (refreshed) {
          ok = await tryAuthCheck();
          console.log('Resultado tras refresh:', ok);
        }
      }

      if (ok) {
        isAuthenticated = true;
        updateAuthUI();
        await loadConfig().catch(()=>{});
        await load().catch(()=>{});
        return true;
      }

      // Si no hay sesión válida, dejamos que el frontend gestione la limpieza.
      isAuthenticated = false;
      jwtToken = '';
      try { localStorage.removeItem('admin_jwt'); } catch(_){}
      try { sessionStorage.removeItem('admin_jwt'); } catch(_){}
      updateAuthUI();

      // Evitar redirecciones inmediatas en el caso de comprobaciones intermitentes.
      if (redirectIfNot) {
        // Si ya estamos en /auth no redirigimos; si no, redirigimos.
        if (!window.location.pathname.endsWith('/auth')) {
          // Pequeña espera para evitar bucles por comprobaciones rápidas
          setTimeout(() => { window.location.replace('/auth'); }, 200);
        }
      }
      return false;
    } catch (err) {
      console.error('Error en checkAuth:', err);
      isAuthenticated = false;
      jwtToken = '';
      try { localStorage.removeItem('admin_jwt'); } catch(_){}
      try { sessionStorage.removeItem('admin_jwt'); } catch(_){}
      updateAuthUI();
      if (redirectIfNot && !window.location.pathname.endsWith('/auth')) {
        setTimeout(() => { window.location.replace('/auth'); }, 200);
      }
      return false;
    }
  
    }

  // --- CRUD: create / update / delete ---
  async function create(){
    const qv = ($('#q') && $('#q').value) || '';
    const av = ($('#a') && $('#a').value) || '';
    if (!qv.trim()){
      Swal.fire('Error', 'La pregunta no puede estar vacía', 'error');
      return;
    }
    const fd = new FormData();
    fd.append('question', qv);
    fd.append('answer', av);
    try{
      const res = await fetchWithRetry('/api/v1/admin/qa', { method: 'POST', _rawHeaders: getAuthHeaders(), body: fd });
      if (res.ok){
        Swal.fire('Éxito','Q&A creada correctamente','success');
        if($('#q')) $('#q').value='';
        if($('#a')) $('#a').value='';
        await load();
      } else {
        let msg = 'No se pudo crear Q&A';
        try { const j = await res.json(); if (j && j.detail) msg = j.detail; } catch(_) {}
        Swal.fire('Error', msg, 'error');
      }
    }catch(err){
      console.error('create error', err);
      Swal.fire('Error','Error de conexión', 'error');
    }
  }

  async function update(id){
    const qEl = document.querySelector(`.q-input[data-id="${id}"]`);
    const aEl = document.querySelector(`.a-text[data-id="${id}"]`);
    if(!qEl || !aEl){ Swal.fire('Error','Elemento no encontrado','error'); return; }
    const fd = new FormData();
    fd.append('question', qEl.value);
    fd.append('answer', aEl.value);
    try{
      const res = await fetchWithRetry(`/api/v1/admin/qa/${id}`, { method: 'PUT', _rawHeaders: getAuthHeaders(), body: fd });
      if(res.ok){ Swal.fire('Éxito','Q&A actualizada','success'); await load(); }
      else { Swal.fire('Error','No se pudo actualizar','error'); }
    }catch(err){
      console.error('update error', err);
      Swal.fire('Error','Error de conexión','error');
    }
  }

  async function del(id){
    const result = await Swal.fire({
      title:'¿Eliminar Q&A?',
      text:'Esta acción no se puede deshacer',
      icon:'warning',
      showCancelButton:true,
      confirmButtonText:'Sí, eliminar',
      cancelButtonText:'Cancelar'
    });
    if(!result.isConfirmed) return;
    try{
      const res = await fetchWithRetry(`/api/v1/admin/qa/${id}`, { method:'DELETE', _rawHeaders: getAuthHeaders() });
      if(res.ok){ Swal.fire('Éxito','Q&A eliminada','success'); await load(); }
      else { Swal.fire('Error','No se pudo eliminar','error'); }
    }catch(err){
      console.error('del error', err);
      Swal.fire('Error','Error de conexión','error');
    }
  }

  // --- Sync / reseed ---
  async function syncSamples(){
    try{
      const res = await fetchWithRetry('/api/v1/admin/sync-samples', { method:'POST', _rawHeaders: getAuthHeaders() });
      if(res.ok){
        const data = await res.json().catch(()=>({synced:false, count:0, message:''}));
        Swal.fire('Sincronización', data.synced ? 'Sincronizado. Insertados: '+data.count : data.message, data.synced ? 'success' : 'info');
        await load();
      } else { Swal.fire('Error','Sync falló','error'); }
    }catch(err){
      console.error('syncSamples error',err);
      Swal.fire('Error','Error de conexión','error');
    }
  }

  async function reseed(){
    const result = await Swal.fire({
      title:'Reseed completo',
      text:'Esto borrará todas las Q&A y recargará samples_seed.json',
      icon:'warning',
      showCancelButton:true,
      confirmButtonText:'Sí, continuar',
      cancelButtonText:'Cancelar'
    });
    if(!result.isConfirmed) return;
    try{
      const res = await fetchWithRetry('/api/v1/admin/reseed', { method:'POST', _rawHeaders: getAuthHeaders() });
      if(res.ok){ const data = await res.json().catch(()=>({count:0})); Swal.fire('Éxito','Reseed OK. Insertados: '+data.count,'success'); await load(); }
      else { Swal.fire('Error','Reseed falló','error'); }
    }catch(err){
      console.error('reseed error', err);
      Swal.fire('Error','Error de conexión','error');
    }
  }

  // --- Config endpoints ---
  async function loadConfig(){
    try{
      let res = await fetchWithRetry('/api/v1/admin/config', { method:'GET', _rawHeaders: getAuthHeaders() });
      // Si recibimos 401 intentamos refrescar token y reintentar una vez
      if (res.status === 401) {
        console.debug('loadConfig recibió 401 — intentando refresh antes de fallar');
        const refreshed = await refreshToken();
        if (refreshed) {
          res = await fetchWithRetry('/api/v1/admin/config', { method:'GET', _rawHeaders: getAuthHeaders() });
        }
      }
      if (res.ok){
        const data = await res.json();
        if($('#thresh')) $('#thresh').value = data.THRESH;
        if($('#maxHistory')) $('#maxHistory').value = data.MAX_HISTORY;
      } else {
        console.warn('loadConfig no ok', res.status);
      }
    }catch(err){
      console.error('loadConfig error', err);
    }
  }

  async function saveConfig(){
    const fd = new FormData();
    if($('#thresh')) fd.append('thresh', $('#thresh').value);
    if($('#maxHistory')) fd.append('max_history', $('#maxHistory').value);
    try{
      const res = await fetchWithRetry('/api/v1/admin/config', { method:'POST', _rawHeaders: getAuthHeaders(), body: fd });
      if(res.ok) Swal.fire('Éxito','Configuración guardada en base de datos','success');
      else Swal.fire('Error','No se pudo guardar','error');
    }catch(err){
      console.error('saveConfig error', err);
      Swal.fire('Error','Error de conexión','error');
    }
  }

  // --- Load list (public or admin) ---
  async function load(){
    const list = $('#list');
    if(!list) return;
    list.innerHTML = '<div class="muted">Cargando...</div>';
    try{
      list.innerHTML = '';
      if(isAuthenticated){
        let res = await fetchWithRetry('/api/v1/admin/qa', { method: 'GET', _rawHeaders: getAuthHeaders() });
        if (res.status === 401) {
          console.debug('load recibió 401 — intentando refresh');
          const refreshed = await refreshToken();
          if (refreshed) {
            res = await fetchWithRetry('/api/v1/admin/qa', { method: 'GET', _rawHeaders: getAuthHeaders() });
          }
        }
        if(!res.ok) throw new Error('Error cargando QA admin: ' + res.status);
        const data = await res.json();
        data.qa.forEach(item => {
          const div = document.createElement('div');
          div.className = 'item';
          div.innerHTML = `
            <div class="muted">ID ${item.id}</div>
            <div class="grid">
              <div>Pregunta</div>
              <input value="${escapeHtml(item.question)}" class="q-input" data-id="${item.id}">
              <div>Respuesta</div>
              <textarea class="a-text" data-id="${item.id}" rows="3">${escapeHtml(item.answer||'')}</textarea>
            </div>
            <div style="margin-top:8px" class="row">
              <button class="btn btn-save" data-id="${item.id}">Guardar</button>
              <button class="btn danger btn-del" data-id="${item.id}">Eliminar</button>
            </div>
          `;
          list.appendChild(div);
        });
      } else {
        const res = await fetchWithRetry('/api/v1/questions?limit=100', { method: 'GET' });
        if(!res.ok) throw new Error('Error cargando preguntas públicas: ' + res.status);
        const data = await res.json();
        data.questions.forEach(item => {
          const div = document.createElement('div');
          div.className = 'item auth-required';
          div.innerHTML = `
            <div class="muted">ID ${item.id}</div>
            <div class="grid">
              <div>Pregunta</div>
              <input value="${escapeHtml(item.question)}" class="q-input" data-id="${item.id}">
              <div>Respuesta</div>
              <textarea class="a-text" data-id="${item.id}" rows="3" placeholder="Ingresa API Key para ver respuesta"></textarea>
            </div>
            <div style="margin-top:8px" class="row">
              <button class="btn btn-save" data-id="${item.id}">Guardar</button>
              <button class="btn danger btn-del" data-id="${item.id}">Eliminar</button>
            </div>
          `;
          list.appendChild(div);
        });
      }

      $$('.btn-save').forEach(b => b.addEventListener('click', () => update(parseInt(b.dataset.id, 10))));
      $$('.btn-del').forEach(b => b.addEventListener('click', () => del(parseInt(b.dataset.id, 10))));
      updateAuthUI();
    }catch(err){
      list.innerHTML = `<div class="muted">No se pudo cargar el listado: ${escapeHtml(err.message || err)}</div>`;
      console.error(err);
    }
  }

  // --- Login / Register / Logout ---
  async function loginHandler(e){
    if(e && e.preventDefault) e.preventDefault();
    const email = ($('#email') && $('#email').value.trim()) || '';
    const password = ($('#password') && $('#password').value) || '';
    if (!email || !password) return Swal.fire('Error','Email y contraseña requeridos','error');

    $('#btnLogin').disabled = true;
    try{
      const res = await fetchWithRetry('/api/v1/auth/login', {
        method:'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ email, password })
      });
      if (!res.ok){
        let message = res.statusText;
        try{ const j = await res.json(); if(j && j.detail) message = j.detail; } catch(_) {}
        Swal.fire('Error','Credenciales inválidas: ' + message, 'error');
        $('#btnLogin').disabled = false;
        return;
      }
      let json = null;
      try{ json = await res.json(); }catch(_){}
      if (json && json.token){
        jwtToken = json.token;
        localStorage.setItem('admin_jwt', jwtToken);
        try { sessionStorage.setItem('justLoggedInAt', Date.now().toString()); } catch(e) {}
      }
      const ok = await checkAuth();
      if (ok){
        location.replace('/admin');
      } else {
        Swal.fire('Error','No fue posible validar sesión tras login','error');
      }
    }catch(err){
      console.error('loginHandler error', err);
      Swal.fire('Error','Error de conexión o servidor: ' + (err.message || err), 'error');
    } finally {
      $('#btnLogin').disabled = false;
    }
  }

  async function registerHandler(){
    const email = ($('#email') && $('#email').value.trim()) || '';
    const password = ($('#password') && $('#password').value) || '';
    if(!email || !password || password.length < 6) return Swal.fire('Error','Contraseña mínima de 6 caracteres','error');
    $('#btnRegister').disabled = true;
    try{
      const res = await fetchWithRetry('/api/v1/auth/register', {
        method:'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ email, password })
      });
      if(!res.ok){
        let message = res.statusText;
        try{ const j = await res.json(); if(j && j.detail) message = j.detail; }catch(_){}
        Swal.fire('Error', message, 'error');
      } else {
        Swal.fire('Éxito','Usuario registrado. Ahora puedes iniciar sesión.','success');
      }
    }catch(err){
      console.error('registerHandler error', err);
      Swal.fire('Error','Error de conexión: '+(err.message||err),'error');
    } finally {
      $('#btnRegister').disabled = false;
    }
  }

  async function logoutHandler(){
    try{
      await fetchWithRetry('/api/v1/auth/logout', { method: 'POST' }).catch(()=>{});
    }catch(_){}
    jwtToken = '';
    localStorage.removeItem('admin_jwt');
    deleteCookie('admin_jwt');
    isAuthenticated = false;
    updateAuthUI();
    location.replace('/auth');
  }

  // --- Wire events (run after all functions are declared) ---
  function wire(){
    $('#btnCreate')?.addEventListener('click', create);
    $('#btnLoadConfig')?.addEventListener('click', loadConfig);
    $('#btnSaveConfig')?.addEventListener('click', saveConfig);
    $('#btnSync')?.addEventListener('click', syncSamples);
    $('#btnReseed')?.addEventListener('click', reseed);

    // login form submit triggers loginHandler (Enter will submit)
    $('#loginForm')?.addEventListener('submit', loginHandler);
    $('#btnRegister')?.addEventListener('click', registerHandler);
    $('#btnLogout')?.addEventListener('click', logoutHandler);

    // apiKey change triggers auth check
    $('#apiKey')?.addEventListener('change', () => checkAuth());
  }

  // --- Init ---
  window.addEventListener('load', async () => {
    wire();

    try {
        const isAuthPage = window.location.pathname.endsWith('/auth');
        const isAuthenticated = await checkAuth();
        
        console.log('Estado de autenticación:', isAuthenticated);
        console.log('Es página de auth:', isAuthPage);
        
        if (isAuthPage && isAuthenticated) {
            console.log('Redirigiendo a admin desde auth...');
            window.location.replace('/admin');
        } else if (!isAuthPage && !isAuthenticated) {
            console.log('Redirigiendo a auth desde admin...');
            window.location.replace('/auth');
        } else {
            console.log('Cargando datos...');
            await load();
        }
    } catch (error) {
        console.error('Error durante inicialización:', error);
        if (!window.location.pathname.endsWith('/auth')) {
            window.location.replace('/auth');
        }
    }
  });

})();
