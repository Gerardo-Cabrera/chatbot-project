// auth.js - Versión completamente revisada y depurada
(function(){
  const form = document.getElementById('loginForm');
  const loginBtn = document.getElementById('loginBtn');
  const registerBtn = document.getElementById('registerBtn');

  // Función robusta para establecer cookies
  function setCookie(name, value, days) {
    try {
      const d = new Date(); 
      d.setTime(d.getTime() + (days * 24 * 60 * 60 * 1000));
      const expires = "expires=" + d.toUTCString();
      document.cookie = `${name}=${value};${expires};path=/;SameSite=Lax`;
      console.log('Cookie establecida:', name, value);
      return true;
    } catch (e) {
      console.error('Error al establecer cookie:', e);
      return false;
    }
  }

  // Función para verificar si el almacenamiento está disponible
  function isStorageAvailable() {
    try {
      const test = 'test';
      localStorage.setItem(test, test);
      localStorage.removeItem(test);
      return true;
    } catch (e) {
      console.warn('LocalStorage no disponible:', e);
      return false;
    }
  }

  // Almacenamiento redundante de token
  function storeAuthToken(token) {
    // Nota: Para máxima seguridad, no almacenamos tokens en localStorage/sessionStorage.
    // El backend debe emitir una cookie HttpOnly ('admin_jwt') que el navegador enviará
    // automáticamente en futuras peticiones. Esta función queda como no-operativa por
    // seguridad (se mantiene para compatibilidad si se necesita en el futuro).
    console.warn('storeAuthToken no usa almacenamiento del lado cliente por razones de seguridad');
    return false;
  }

  async function handleLogin(e) {
    if(e) e.preventDefault();
    if(loginBtn.disabled) return;
    
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    
    if(!email || !password) { 
      alert('Email y contraseña requeridos'); 
      return; 
    }

    loginBtn.disabled = true;
    const originalText = loginBtn.textContent;
    loginBtn.textContent = 'Iniciando sesión...';

    try {
      console.log('Enviando solicitud de login...');
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({email, password}),
        credentials: 'include'
      });

      console.log('Respuesta recibida, status:', res.status);
      
      if(!res.ok) {
        let message = 'Error en el login';
        try {
          const j = await res.json();
          message = j.detail || j.error || message;
        } catch(_) {}
        throw new Error(message);
      }

      const data = await res.json();
      console.log('Datos de respuesta:', data);
      
      // El backend ya estableció la cookie HttpOnly 'admin_jwt' (credentials: 'include').
      // No almacenamos el token en el cliente por seguridad. Simplemente redirigimos
      // al panel de administración; la sesión será verificada por /admin cuando sea necesario.
      console.log('Login exitoso (backend respondió OK). Redirigiendo a /admin');
      window.location.replace('/admin');
    } catch(err) {
      console.error('Error en login:', err);
      alert('Error: ' + err.message);
    } finally {
      loginBtn.disabled = false;
      loginBtn.textContent = originalText;
    }
  }

  // Función auxiliar para obtener cookies
  function getCookie(name) {
    try {
      const value = `; ${document.cookie}`;
      const parts = value.split(`; ${name}=`);
      if (parts.length === 2) return parts.pop().split(';').shift();
    } catch (e) {
      console.error('Error al leer cookie:', e);
    }
    return null;
  }

  async function handleRegister() {
    if(registerBtn.disabled) return;
    registerBtn.disabled = true;
    
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    
    if(!email || !password || password.length < 6) {
      alert('Contraseña mínima de 6 caracteres'); 
      registerBtn.disabled = false; 
      return;
    }

    try {
      const res = await fetch('/api/v1/auth/register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email, password}),
        credentials: 'include'
      });
      
      if(!res.ok) {
        const t = await res.json().catch(() => ({detail: 'Registro inválido'}));
        alert(t.detail || 'Registro inválido');
      } else {
        alert('Registro exitoso. Ahora inicia sesión.');
      }
    } catch(err) {
      console.error('Register error', err);
      alert('Error de conexión');
    } finally {
      registerBtn.disabled = false;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    console.log('Página de auth cargada');
    
    // Verificar si el almacenamiento está disponible
    if (!isStorageAvailable()) {
      console.warn('El almacenamiento local no está disponible');
      alert('Advertencia: El almacenamiento local no está disponible. Es posible que la sesión no se mantenga.');
    }
    
    // Verificar sesión con endpoint ligero /auth/status (usa cookie HttpOnly)
    console.log('Verificando sesión con /api/v1/auth/status...');
    fetch('/api/v1/auth/status', { method: 'GET', credentials: 'include' })
      .then(res => {
        if (res.ok) {
          console.log('Sesión activa detectada, redirigiendo a /admin');
          window.location.replace('/admin');
        } else {
          console.log('No hay sesión activa');
        }
      })
      .catch(err => {
        console.error('Error al verificar sesión:', err);
      });
    
    // Manejo del submit
    form.addEventListener('submit', handleLogin);
    // Evitar que el botón haga doble submit
    loginBtn.addEventListener('click', (ev) => {
      // El submit del formulario manejará la lógica, así que dejamos que se procese normalmente
      // Pero prevenimos acciones duplicadas si el botón está deshabilitado
      if (loginBtn.disabled) ev.preventDefault();
    });

    // Soporte para la tecla Enter en los inputs: simula el submit del formulario
    ['email','password'].forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter') {
          ev.preventDefault();
          // Disparar submit del formulario que llama a handleLogin
          form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
        }
      });
    });
    registerBtn.addEventListener('click', handleRegister);
  });
})();