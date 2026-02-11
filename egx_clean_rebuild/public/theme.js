// Theme toggle (light/dark) with localStorage
(function(){
  const KEY = "egx_theme";
  function apply(t){
    const theme = (t === "light") ? "light" : "dark";
    document.body.setAttribute("data-theme", theme);
    const toggle = document.getElementById("themeToggle");
    if(toggle) toggle.checked = (theme === "dark"); // checked = dark
  }
  function init(){
    const saved = localStorage.getItem(KEY) || "dark";
    apply(saved);
    const toggle = document.getElementById("themeToggle");
    if(toggle){
      toggle.addEventListener("change", ()=>{
        const t = toggle.checked ? "dark" : "light";
        localStorage.setItem(KEY, t);
        apply(t);
      });
    }
  }
  document.addEventListener("DOMContentLoaded", init);
})();