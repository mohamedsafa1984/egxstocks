import { STOCKS } from "./stocks.js";

function $(id){ return document.getElementById(id); }

function getToken(){ return localStorage.getItem("token"); }
function getUser(){
  try { return JSON.parse(localStorage.getItem("user") || "null"); } catch { return null; }
}

function fillSelect(sel, items, selected){
  sel.innerHTML = "";
  for(const it of items){
    const opt = document.createElement("option");
    opt.value = it;
    opt.textContent = it;
    sel.appendChild(opt);
  }
  if(selected && items.includes(selected)) sel.value = selected;
}

function fmtDate(iso){
  try{
    const d = new Date(iso);
    return d.toLocaleString("ar-EG");
  }catch{ return iso || ""; }
}

async function loadRecommendations(){
  const token = getToken();
  const user = getUser();
  const role = String(user?.role || '').toLowerCase();
  const canRecManage = !!user && (role === 'admin' || role === 'ceo' || role === 'admin_rcmd');
  const canHideAll = !!user && (role === 'admin' || role === 'ceo');
  const canHideBasic = canHideAll;
  const canDeleteRec = canHideAll;
  const url = canRecManage ? "/api/admin/recommendations" : "/api/recommendations";
  const res = await fetch(url, canRecManage && token ? { headers: { "Authorization": "Bearer " + token } } : undefined);
  const rows = await res.json();
  const filterStock = (window.__recStockFilter || "").trim().toUpperCase();
  const body = $("recBody");
  body.innerHTML = "";
  const showHidden = window.__showHidden === true;
  for(const r of rows){
    if (filterStock && String(r.stock||"").toUpperCase() !== filterStock) continue;
    if (!canRecManage && r.hidden) continue;
    if (canRecManage && !showHidden && r.hidden) continue;
    const tr = document.createElement("tr");
    if (r.hidden) tr.classList.add('isHidden');
    if (r.hidden_basic) tr.classList.add('isBasicHidden');
    tr.innerHTML = `
      <td>${renderConfidenceCell(r, canRecManage)}</td>
      <td>${escapeHtml(r.analyst || "")}</td>
      <td><b>${escapeHtml((r.stock||"").toUpperCase())}</b></td>
      <td>${r.entry_price ?? ""}</td>
      <td>${r.take_profit ?? ""}</td>
      <td>${profitPctCell(r)}</td>
      <td>${renderRecGradeCell(r, canRecManage)}</td>
      <td>${fmtDate(r.rec_date || "")}</td>
      <td>${fmtDate(r.exit_date || "")}</td>
      <td title="${escapeHtml(r.notes || "")}">${escapeHtml(shorten(r.notes || "", 40))}</td>
      <td>${fmtDate(r.created_at)}</td>
      ${canRecManage ? `<td>${adminButtons(r, { canHideAll, canHideBasic, canDeleteRec })}</td>` : ``}
    `;
    body.appendChild(tr);
  }
}

const CONF_LEVELS = ["", "A++", "A", "B", "C", "D"];
const REC_GRADES = ["", "A", "B", "C", "D"]; 

function calcProfitPct(entry, target){
  const e = parseFloat(entry);
  const t = parseFloat(target);
  if (!isFinite(e) || !isFinite(t) || e <= 0) return null;
  return ((t - e) / e) * 100;
}

function profitPctCell(r){
  const p = (r && r.profit_pct != null) ? parseFloat(r.profit_pct) : calcProfitPct(r?.entry_price, r?.take_profit);
  if (!isFinite(p)) return "";
  return `${p.toFixed(2)}%`;
}

function renderConfidenceCell(r, canManage){
  const val = (r.analyst_confidence || "").trim();
  if(!canManage) return escapeHtml(val);
  return `<select class="miniSel rankSel" data-id="${r.id}" data-field="analyst_confidence">
    ${CONF_LEVELS.map(x => `<option value="${escapeHtml(x)}" ${x===val?'selected':''}>${escapeHtml(x||"-")}</option>`).join('')}
  </select>`;
}

function renderRecGradeCell(r, canManage){
  const val = (r.rec_grade || "").trim();
  if(!canManage) return escapeHtml(val);
  return `<select class="miniSel gradeSel" data-id="${r.id}" data-field="rec_grade">
    ${REC_GRADES.map(x => `<option value="${escapeHtml(x)}" ${x===val?'selected':''}>${escapeHtml(x||"-")}</option>`).join('')}
  </select>`;
}

function setRecFilter(symbol){
  const s = (symbol || "").trim().toUpperCase();
  window.__recStockFilter = s;
  const bar = $("recFilterBar");
  const txt = $("recFilterText");
  if (!bar || !txt) return;
  if (!s) {
    bar.style.display = "none";
    txt.textContent = "";
  } else {
    bar.style.display = "";
    txt.textContent = `عرض توصيات السهم: ${s}`;
  }
}

function adminButtons(r, perms){
  const hid = r.hidden ? 1 : 0;
  const label = hid ? "إظهار" : "إخفاء";
  const bHid = r.hidden_basic ? 1 : 0;
  const bLabel = bHid ? "إظهار للبيسك" : "إخفاء عن البيسك";
  return `
    <div class="adminBtns">
      ${perms?.canHideAll ? `<button class="btn btn-ghost btn-sm" data-act="toggleHide" data-id="${r.id}" data-hidden="${hid}">${label}</button>` : ``}
      ${perms?.canHideBasic ? `<button class="btn btn-ghost btn-sm" data-act="toggleHideBasic" data-id="${r.id}" data-hidden-basic="${bHid}">${bLabel}</button>` : ``}
      <button class="btn btn-ghost btn-sm" data-act="editRec" data-id="${r.id}">تعديل</button>
      ${perms?.canDeleteRec ? `<button class="btn btn-warn btn-sm" data-act="delRec" data-id="${r.id}">حذف</button>` : ``}
    </div>
  `;
}

function shorten(s, n){
  if(s.length <= n) return s;
  return s.slice(0,n-1) + "…";
}
function escapeHtml(str){
  return String(str)
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

function syncAuthUI(){
  const token = getToken();
  const user = getUser();
  const logoutBtn = $("logoutBtn");
  const loginLink = document.getElementById("loginLink");
  const signupLink = document.getElementById("signupLink");
  const pwPanel = $("pwPanel");
  const changePassBtn = $("changePassBtn");

  // Defensive: some pages (login/signup) don't have these elements.
  if (logoutBtn) logoutBtn.style.display = token ? "" : "none";

  if (token && user) {
    if (signupLink) signupLink.style.display = "none";
    if (loginLink) {
      loginLink.textContent = user.username || "الحساب";
      loginLink.href = "#";
      loginLink.classList.add("user-chip");
    }
    if (pwPanel) pwPanel.style.display = "none";
    if (changePassBtn) changePassBtn.style.display = "none";
    if (changePassBtn) changePassBtn.style.display = "";
  } else {
    if (signupLink) signupLink.style.display = "";
    if (loginLink) {
      loginLink.textContent = "تسجيل دخول";
      loginLink.href = "login.html";
      loginLink.classList.remove("user-chip");
    }
    if (pwPanel) pwPanel.style.display = "none";
    if (changePassBtn) changePassBtn.style.display = "none";
  }
}

function openModal(){
  const m = $("addModal");
  m.setAttribute("aria-hidden","false");
  // default recommendation date = today
  const rd = $("addRecDate");
  if(rd && !rd.value){
    const t = new Date();
    const yyyy = t.getFullYear();
    const mm = String(t.getMonth()+1).padStart(2,"0");
    const dd = String(t.getDate()).padStart(2,"0");
    rd.value = `${yyyy}-${mm}-${dd}`;
  }
}
function closeModal(){
  const m = $("addModal");
  m.setAttribute("aria-hidden","true");
}

async function addRecommendation(payload){
  const token = getToken();
  const hint = $("addRecHint");
  if(!token){
    hint.textContent = "لازم تسجل دخول الأول.";
    hint.style.color = "#ff7b7b";
    return;
  }
  hint.textContent = "جاري الحفظ...";
  hint.style.color = "";

  const res = await fetch("/api/recommendations",{
    method:"POST",
    headers:{
      "Content-Type":"application/json",
      "Authorization":"Bearer " + token
    },
    body: JSON.stringify(payload)
  });
  const data = await res.json().catch(()=>null);

  if(res.ok){
    hint.textContent = "تمت الإضافة ✅";
    await loadRecommendations();
    setTimeout(()=>{ closeModal(); hint.textContent=""; }, 600);
  }else{
    hint.textContent = (data && data.message) ? data.message : "فشل إضافة التوصية";
    hint.style.color = "#ff7b7b";
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  // Stocks select + chart
  const stockSelect = $("stockSelect");
  const addStock = $("addStock");
  fillSelect(stockSelect, STOCKS, "COMI");
  fillSelect(addStock, STOCKS, "COMI");

  // initial chart
  if(window.setTVSymbol) window.setTVSymbol(stockSelect.value);
  // default: show recommendations for selected stock
  setRecFilter(stockSelect.value);

  stockSelect.addEventListener("change", () => {
    const t = stockSelect.value;
    if(window.setTVSymbol) window.setTVSymbol(t);
    setRecFilter(t);
    loadRecommendations();
  });

  // Search bar
  const search = $("stockSearch");
  search.addEventListener("keydown", (e) => {
    if(e.key !== "Enter") return;
    e.preventDefault();
    const q = search.value.trim().toUpperCase();
    if(!q) return;
    if(STOCKS.includes(q)){
      stockSelect.value = q;
      if(window.setTVSymbol) window.setTVSymbol(q);
      setRecFilter(q);
      loadRecommendations();
      search.value = "";
    } else {
      alert("السهم غير موجود في القائمة");
    }
  });

  const clearBtn = $("clearRecFilterBtn");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      setRecFilter("");
      loadRecommendations();
    });
  }

  // Auth buttons
  syncAuthUI();
  // Toggle change password panel from header button
  const changePassBtn = $("changePassBtn");
  const pwPanel = $("pwPanel");
  if (changePassBtn && pwPanel) {
    changePassBtn.addEventListener("click", () => {
      pwPanel.style.display = (pwPanel.style.display === "none" || pwPanel.style.display === "") ? "" : "none";
      if (pwPanel.style.display !== "none") {
        // focus first field
        const f = $("cpCurrent");
        if (f) f.focus();
      }
    });
  }

  $("logoutBtn").addEventListener("click", () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    syncAuthUI();
    alert("تم تسجيل الخروج");
  });

  // Change password (after login)
  const cpForm = $("changePassForm");
  if (cpForm) {
    const cpShow = $("cpShow");
    const cpMsg = $("changePassMsg");

    if (cpShow) {
      cpShow.addEventListener("change", () => {
        const t = cpShow.checked ? "text" : "password";
        [$("cpCurrent"), $("cpNew"), $("cpNew2")].forEach((el) => {
          if (el) el.type = t;
        });
      });
    }

    cpForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!cpMsg) return;
      cpMsg.textContent = "...";
      const token = getToken();
      if (!token) {
        cpMsg.textContent = "لازم تسجل دخول الأول.";
        return;
      }
      const cur = $("cpCurrent")?.value || "";
      const n1 = $("cpNew")?.value || "";
      const n2 = $("cpNew2")?.value || "";
      if (n1 !== n2) {
        cpMsg.textContent = "كلمتا المرور غير متطابقتين";
        return;
      }
      const res = await fetch("/api/change_password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + token
        },
        body: JSON.stringify({ currentPassword: cur, newPassword: n1 })
      });
      const data = await res.json().catch(() => null);
      if (res.ok) {
        if (data?.token) localStorage.setItem("token", data.token);
        cpMsg.textContent = "تم تحديث كلمة المرور ✅";
        // clear
        if ($("cpCurrent")) $("cpCurrent").value = "";
        if ($("cpNew")) $("cpNew").value = "";
        if ($("cpNew2")) $("cpNew2").value = "";
      } else {
        cpMsg.textContent = (data && data.message) ? data.message : "فشل تحديث كلمة المرور";
      }
    });
  }

  // Modal open/close
  $("openAddModalBtn").addEventListener("click", () => openModal());
  $("closeAddModalBtn").addEventListener("click", () => closeModal());
  $("addModal").addEventListener("click", (e) => {
    if(e.target && e.target.id === "addModal") closeModal();
  });

  // Add form
  const addEntry = $("addEntry");
  const addTarget = $("addTarget");
  const addProfitPct = $("addProfitPct");

  function refreshAddProfitPct(){
    if (!addProfitPct) return;
    const p = calcProfitPct(addEntry?.value, addTarget?.value);
    addProfitPct.value = (p==null || !isFinite(p)) ? "" : `${p.toFixed(2)}%`;
  }
  if (addEntry) addEntry.addEventListener('input', refreshAddProfitPct);
  if (addTarget) addTarget.addEventListener('input', refreshAddProfitPct);
  refreshAddProfitPct();

  $("addRecForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    await addRecommendation({
      stock: $("addStock").value,
      entry_price: $("addEntry").value,
      take_profit: $("addTarget").value,
      profit_pct: calcProfitPct($("addEntry").value, $("addTarget").value),
      rec_date: $("addRecDate") ? $("addRecDate").value : null,
      entry_date: $("addEntryDate") ? $("addEntryDate").value : null,
      exit_date: $("addExitDate") ? $("addExitDate").value : null,
      notes: $("addNotes").value
    });
  });

  // Load table
  // Admin/CEO UI
  await initAdminPanel();

  await loadRecommendations();
});


async function loadSiteSettings(){
  const token = getToken();
  const cb = $("registrationToggle");
  const msg = $("registrationMsg");
  if (!token || !cb) return;
  if (msg) msg.textContent = "";
  const res = await fetch("/api/admin/settings", { headers: { "Authorization": "Bearer " + token } });
  const data = await res.json().catch(()=>null);
  if (res.ok && data) {
    cb.checked = !!data.registration_open;
  } else {
    if (msg) msg.textContent = "تعذر تحميل الإعدادات";
  }
}

async function setRegistrationOpen(open){
  const token = getToken();
  const msg = $("registrationMsg");
  if (!token) return;
  if (msg) msg.textContent = "...";
  const res = await fetch("/api/admin/settings/registration", {
    method: "PUT",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
    body: JSON.stringify({ open: !!open })
  });
  const data = await res.json().catch(()=>null);
  if (res.ok) {
    if (msg) msg.textContent = open ? "التسجيل مفتوح ✅" : "التسجيل مقفول ⛔";
  } else {
    if (msg) msg.textContent = (data && data.message) ? data.message : "فشل";
  }
}

async function initAdminPanel(){
  const user = getUser();
  const token = getToken();
  const adminPanel = $("adminPanel");
  const adminColHead = $("adminColHead");
  const toggleBtn = $("toggleShowHiddenBtn");

  const role = String(user?.role || '').toLowerCase();
  const isAdminish = !!user && (role === 'ceo' || role === 'admin' || role === 'admin_add' || role === 'admin_del' || role === 'admin_rcmd' || role === 'admin_block');
  const canRecManage = !!user && (role === 'admin' || role === 'ceo' || role === 'admin_rcmd');
  const canUserMgmt = !!user && (role === 'admin' || role === 'ceo' || role === 'admin_add' || role === 'admin_del' || role === 'admin_block');
  const canSiteSettings = !!user && (role === 'admin' || role === 'ceo');

  window.__showHidden = false;

  if (adminPanel) adminPanel.style.display = isAdminish ? "" : "none";
  if (adminColHead) adminColHead.style.display = canRecManage ? "" : "none";

  // Site settings block should be visible ONLY for Admin/CEO
  const siteSettingsBlock = $("siteSettingsBlock");
  if (siteSettingsBlock) siteSettingsBlock.style.display = canSiteSettings ? "" : "none";

  if (isAdminish) {
    const roleLine = $("adminRoleLine");
    if (roleLine) roleLine.textContent = `صلاحيتك: ${user.role}`;

    // Site settings (Admin/CEO only)
    if (canSiteSettings) {
      const regCb = $("registrationToggle");
      if (regCb) {
        await loadSiteSettings();
        regCb.addEventListener("change", async () => {
          await setRegistrationOpen(regCb.checked);
        });
      }
    }

    // User management visibility
    const userMgmtBlock = $("userMgmtBlock");
    if (userMgmtBlock) userMgmtBlock.style.display = canUserMgmt ? "" : "none";

    // Create user form visibility + role options
    const createForm = $("createUserForm");
    const createRoleSel = $("newUserRole");
    const canAddUser = (role === 'admin' || role === 'ceo' || role === 'admin_add');
    if (createForm) createForm.style.display = canAddUser ? "" : "none";
    if (createRoleSel && role === 'admin_add') {
      // admin_add can create basic/user only
      createRoleSel.innerHTML = `
        <option value="basic">basic</option>
        <option value="user">user</option>
      `;
    }
  }

  if (canRecManage) {
    // Table action delegation
    const recTable = $("recTable");
    recTable.addEventListener("click", async (e) => {
      const btn = e.target?.closest?.("button[data-act]");
      if (!btn) return;
      const act = btn.getAttribute("data-act");
      const id = btn.getAttribute("data-id");
      if (act === 'toggleHide') {
        const hidden = btn.getAttribute("data-hidden") === '1';
        await toggleHideRec(id, !hidden);
        return;
      }
      if (act === 'toggleHideBasic') {
        const hiddenBasic = btn.getAttribute("data-hidden-basic") === '1';
        await toggleHideBasicRec(id, !hiddenBasic);
        return;
      }
      if (act === 'delRec') {
        await deleteRec(id);
        return;
      }
      if (act === 'editRec') {
        await editRecPrompt(id);
        return;
      }
    });

    if (toggleBtn) {
      toggleBtn.addEventListener("click", async () => {
        window.__showHidden = !window.__showHidden;
        await loadRecommendations();
      });
    }

    // Ranking dropdown change delegation
    recTable.addEventListener('change', async (e) => {
      const sel = e.target?.closest?.('select[data-field]');
      if (!sel) return;
      const id = sel.getAttribute('data-id');
      const field = sel.getAttribute('data-field');
      const value = sel.value;
      await updateRecField(id, { [field]: value });
      await loadRecommendations();
    });
  }

  // User management block (Admin/CEO)
  const userMgmtBlock = $("userMgmtBlock");
  if (userMgmtBlock) userMgmtBlock.style.display = canUserMgmt ? "" : "none";
  if (canUserMgmt) {
    await refreshAllUsers();
    const userSearch = $("userEmailSearch");
    if (userSearch) {
      userSearch.addEventListener("input", () => renderUsersFromCache());
    }
    const roleFilter = $("userRoleFilter");
    if (roleFilter) {
      roleFilter.addEventListener("change", () => {
        syncRoleChips();
        renderUsersFromCache();
      });
    }

    // Quick role chips
    const roleChips = document.querySelectorAll('#roleChips button[data-role]');
    if (roleChips && roleChips.length && roleFilter) {
      roleChips.forEach(btn => {
        btn.addEventListener('click', () => {
          const r = btn.getAttribute('data-role');
          roleFilter.value = (r === null) ? '' : r;
          syncRoleChips();
          renderUsersFromCache();
        });
      });
      syncRoleChips();
    }

    const form = $("createUserForm");
    if (form) {
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        await createUser();
      });
    }
    const allUsersTable = $("allUsersTable");
    if (allUsersTable) {
      allUsersTable.addEventListener("click", async (e) => {
        const btn = e.target?.closest?.("button[data-act]");
        if (!btn) return;
        const act = btn.getAttribute("data-act");
        const id = btn.getAttribute("data-id");
        if (act === 'delUser') {
          await deleteUser(id);
          return;
        }
        if (act === 'saveRole') {
          const sel = document.querySelector(`select[data-user-role="${id}"]`);
          const toRole = sel ? sel.value : 'user';
          await updateUserRole(id, toRole);
          return;
        }
        if (act === 'toggleBlock') {
          await toggleUserBlock(id);
          return;
        }
      });
    }
  }
}

// Keep UI chips in sync with the dropdown filter
function syncRoleChips(){
  const roleFilter = $("userRoleFilter");
  if (!roleFilter) return;
  const v = String(roleFilter.value || "").trim().toLowerCase();
  const chips = document.querySelectorAll('#roleChips button[data-role]');
  if (!chips) return;
  chips.forEach(btn => {
    const r = String(btn.getAttribute('data-role') || "").trim().toLowerCase();
    if (r === v) btn.classList.add('active');
    else btn.classList.remove('active');
  });
}

async function toggleHideBasicRec(id, makeHidden){
  const token = getToken();
  if (!token) return;
  await fetch(`/api/recommendations/${id}/hide_basic`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token
    },
    body: JSON.stringify({ hidden_basic: makeHidden })
  });
  await loadRecommendations();
}

async function updateRecField(id, payload){
  const token = getToken();
  if(!token) return;
  await fetch(`/api/admin/recommendations/${id}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token
    },
    body: JSON.stringify(payload)
  });
}

async function toggleHideRec(id, makeHidden){
  const token = getToken();
  if (!token) return;
  await fetch(`/api/recommendations/${id}/hide`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token
    },
    body: JSON.stringify({ hidden: makeHidden })
  });
  await loadRecommendations();
}

async function createUser(){
  const token = getToken();
  const msg = $("createUserMsg");
  if (!token) return;
  msg.textContent = "...";
  const username = $("newAdminUsername").value.trim();
  const email = $("newAdminEmail").value.trim();
  const password = $("newAdminPassword").value;
  const role = $("newUserRole")?.value || 'user';
  const res = await fetch("/api/admin/users", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token
    },
    body: JSON.stringify({ username, email, password, role })
  });
  const data = await res.json().catch(() => null);
  if (res.ok) {
    msg.textContent = "تم ✅";
    $("newAdminUsername").value = "";
    $("newAdminEmail").value = "";
    $("newAdminPassword").value = "";
    await refreshAllUsers();
  } else {
    msg.textContent = (data && data.message) ? data.message : "فشل";
  }
}

async function refreshAllUsers(){
  const token = getToken();
  const body = $("allUsersBody");
  if (!token || !body) return;
  const res = await fetch("/api/admin/users", { headers: { "Authorization": "Bearer " + token } });
  const users = await res.json().catch(()=>[]);
  window.__usersCache = Array.isArray(users) ? users : [];
  renderUsersFromCache();
}

// (duplicate removed)

function renderUsersFromCache(){
  const body = $("allUsersBody");
  if (!body) return;
  const me = getUser();
  const q = ($("userEmailSearch")?.value || "").trim().toLowerCase();
  const roleFilter = String($("userRoleFilter")?.value || "").trim().toLowerCase();
  const myRole = String(me?.role || "").toLowerCase();
  const canRoleEdit = (myRole === 'admin' || myRole === 'ceo');
  const canDeleteUser = (myRole === 'admin' || myRole === 'ceo' || myRole === 'admin_del');
  const canBlockUser = (myRole === 'admin' || myRole === 'ceo' || myRole === 'admin_block');
  const users = Array.isArray(window.__usersCache) ? window.__usersCache : [];
  let filtered = users;
  if (q) filtered = filtered.filter(u => String(u.email||"").toLowerCase().includes(q) || String(u.username||"").toLowerCase().includes(q));
  if (roleFilter) filtered = filtered.filter(u => String(u.role||"").toLowerCase() === roleFilter);

  body.innerHTML = "";
  for (const u of filtered) {
    const isMe = me && Number(me.id) === Number(u.id);
    const isCEO = u.role === 'ceo';
    const tr = document.createElement('tr');
    const canToggle = !(isCEO || isMe) && canRoleEdit;
    const targetRole = String(u.role||"").toLowerCase();
    const delAllowedForThisTarget = canDeleteUser && !(isCEO || isMe) && (myRole !== 'admin_del' || (targetRole === 'basic' || targetRole === 'user'));
    const blockAllowedForThisTarget = canBlockUser && !(isCEO || isMe) && (myRole !== 'admin_block' || (targetRole === 'basic' || targetRole === 'user'));
    tr.innerHTML = `
      <td>${escapeHtml(u.username)}</td>
      <td>${escapeHtml(u.email)}</td>
      <td>
        ${ (isCEO) ? escapeHtml(u.role) : `
          <select class="miniSel" data-user-role="${u.id}" ${!canToggle ? 'disabled' : ''}>
            ${['basic','user','admin_add','admin_del','admin_rcmd','admin_block','admin'].map(r => `<option value="${r}" ${r===u.role?'selected':''}>${r}</option>`).join('')}
          </select>
        ` }
      </td>
      <td>${fmtDate(u.created_at)}</td>
      <td>${u.is_blocked ? "⛔" : "✅"}</td>
      <td>${(isCEO || isMe) ? '<span class="muted">-</span>' : `
        <div class="adminBtns">
          ${canRoleEdit ? `<button class="btn btn-ghost btn-sm" data-act="saveRole" data-id="${u.id}">حفظ</button>` : ``}
          ${blockAllowedForThisTarget ? `<button class="btn btn-ghost btn-sm" data-act="toggleBlock" data-id="${u.id}">${u.is_blocked ? "فك الحظر" : "حظر"}</button>` : ``}
          ${delAllowedForThisTarget ? `<button class="btn btn-warn btn-sm" data-act="delUser" data-id="${u.id}">حذف</button>` : ``}
        </div>
      `}</td>
    `;
    body.appendChild(tr);
  }
}


async function toggleUserBlock(id){
  const token = getToken();
  if (!token) return;
  const me = getUser();
  // fetch current users list to know current state quickly
  const res = await fetch("/api/admin/users", { headers: { "Authorization": "Bearer " + token } });
  const users = await res.json().catch(()=>[]);
  const u = users.find(x => String(x.id) === String(id));
  if (!u) return;
  const nextBlocked = !u.is_blocked;
  const label = nextBlocked ? "حظر" : "فك الحظر";
  if (!confirm(`متأكد تعمل ${label} للمستخدم؟`)) return;
  await fetch(`/api/admin/users/${id}/block`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
    body: JSON.stringify({ blocked: nextBlocked })
  });
  await refreshAllUsers();
}

async function deleteUser(id){
  const token = getToken();
  if (!token) return;
  if (!confirm("متأكد تحذف المستخدم؟")) return;
  await fetch(`/api/admin/users/${id}`, {
    method: "DELETE",
    headers: { "Authorization": "Bearer " + token }
  });
  await refreshAllUsers();
}

async function updateUserRole(id, role){
  const token = getToken();
  if (!token) return;
  await fetch(`/api/admin/users/${id}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token
    },
    body: JSON.stringify({ role })
  });
  await refreshAllUsers();
}

async function deleteRec(id){
  const token = getToken();
  if (!token) return;
  if (!confirm("حذف التوصية نهائياً؟")) return;
  await fetch(`/api/admin/recommendations/${id}`, {
    method: "DELETE",
    headers: { "Authorization": "Bearer " + token }
  });
  await loadRecommendations();
}

async function editRecPrompt(id){
  const token = getToken();
  if (!token) return;
  // fetch current list (already loaded) by hitting admin list and finding item
  const res = await fetch("/api/admin/recommendations", { headers: { "Authorization": "Bearer " + token } });
  const rows = await res.json();
  const r = rows.find(x => String(x.id) === String(id));
  if (!r) return alert("لم يتم العثور على التوصية");

  const analyst = prompt("اسم المحلل", r.analyst ?? "") ?? null;
  if (analyst === null) return;
  const stock = prompt("السهم", (r.stock ?? "").toUpperCase()) ?? null;
  if (stock === null) return;
  const entry = prompt("سعر الدخول", r.entry_price ?? "") ?? null;
  if (entry === null) return;
  const target = prompt("الهدف", r.take_profit ?? "") ?? null;
  if (target === null) return;
  const time = prompt("المدة المتوقعة", r.expected_time ?? "") ?? null;
  if (time === null) return;
  const conf = prompt("ثقة المحلل (A++/A/B/C/D)", (r.analyst_confidence ?? "")) ?? null;
  if (conf === null) return;
  const grade = prompt("جريد التوصية (A/B/C/D)", (r.rec_grade ?? "")) ?? null;
  if (grade === null) return;
  const notes = prompt("الملاحظات", r.notes ?? "") ?? null;
  if (notes === null) return;

  await fetch(`/api/admin/recommendations/${id}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token
    },
    body: JSON.stringify({ analyst, stock, entry_price: entry, take_profit: target, expected_time: time, analyst_confidence: conf, rec_grade: grade, notes })
  });
  await loadRecommendations();

(function () {
  const vp = document.querySelector('#viewport');

  // اختار عرض "الديسكتوب" اللي انت مصمم عليه
  // جرب 1200 أو 1280 حسب شكل موقعك
  const DESIGN_WIDTH_PORTRAIT  = 1200;
  const DESIGN_WIDTH_LANDSCAPE = 1200;

  function applyFitViewport() {
    if (!vp) return;

    // على iOS الأفضل تستخدم screen.width/height مع orientation
    const isLandscape = window.matchMedia("(orientation: landscape)").matches;

    const designWidth = isLandscape ? DESIGN_WIDTH_LANDSCAPE : DESIGN_WIDTH_PORTRAIT;

    // عرض الجهاز الفعلي بالبيكسل المنطقي
    const deviceWidth = Math.min(window.screen.width, window.screen.height) * (isLandscape ? 1 : 1);

    // scale = deviceWidth / designWidth
    // نحط حد أدنى عشان مايبقاش صغير زيادة
    let scale = deviceWidth / designWidth;
    scale = Math.max(scale, 0.22); // عدّلها لو حاسسها صغيرة قوي
    scale = Math.min(scale, 1);

    vp.setAttribute(
      "content",
      `width=${designWidth}, initial-scale=${scale}, viewport-fit=cover, user-scalable=yes`
    );
  }

  window.addEventListener("load", applyFitViewport);
  window.addEventListener("resize", () => setTimeout(applyFitViewport, 150));
  window.addEventListener("orientationchange", () => setTimeout(applyFitViewport, 200));
})();

}
