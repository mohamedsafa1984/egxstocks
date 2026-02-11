const API = "";

function setMsg(id, text, ok=true){
  const el = document.getElementById(id);
  if(!el) return;
  el.textContent = text || "";
  el.style.color = ok ? "" : "#ff7b7b";
}

async function postJSON(url, body){
  const res = await fetch(url, {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify(body)
  });
  let data = null;
  try { data = await res.json(); } catch { data = null; }
  return { res, data };
}

document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("loginForm");
  if(loginForm){
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      setMsg("loginMsg","...");

      const email = document.getElementById("loginEmail").value.trim();
      const password = document.getElementById("loginPassword").value;

      const {res, data} = await postJSON("/api/login", { email, password });
      if(res.ok){
        localStorage.setItem("token", data.token);
        localStorage.setItem("user", JSON.stringify(data.user));
        window.location.href = "index.html";
      }else{
        setMsg("loginMsg", (data && data.message) ? data.message : "فشل تسجيل الدخول", false);
      }
    });
  }

  const signupForm = document.getElementById("signupForm");
  if(signupForm){
    const show = document.getElementById("showSignupPass");
    if(show){
      show.addEventListener("change", ()=>{
        const t = show.checked ? "text" : "password";
        const p1 = document.getElementById("suPassword");
        const p2 = document.getElementById("suPassword2");
        if(p1) p1.type = t;
        if(p2) p2.type = t;
      });
    }

    signupForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      setMsg("signupMsg","...");

      const username = document.getElementById("suUsername").value.trim();
      const email = document.getElementById("suEmail").value.trim();
      const password = document.getElementById("suPassword").value;
      const password2 = document.getElementById("suPassword2") ? document.getElementById("suPassword2").value : password;
      if(password !== password2){
        setMsg("signupMsg","كلمتا المرور غير متطابقتين", false);
        return;
      }

      const {res, data} = await postJSON("/api/signup", { username, email, password });
      if(res.ok){
        setMsg("signupMsg","تم إنشاء الحساب ✅");
        // auto login
        const lg = await postJSON("/api/login", { email, password });
        if(lg.res.ok){
          localStorage.setItem("token", lg.data.token);
          localStorage.setItem("user", JSON.stringify(lg.data.user));
          window.location.href = "index.html";
        } else {
          window.location.href = "login.html";
        }
      }else{
        setMsg("signupMsg", (data && data.message) ? data.message : "فشل إنشاء الحساب", false);
      }
    });
  }
});
