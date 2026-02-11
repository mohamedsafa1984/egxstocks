// TradingView Advanced Chart Widget (simple wrapper)
window.__tv_symbol = "EGX:COMI";

function renderTV(symbol){
  window.__tv_symbol = symbol;
  const container = document.getElementById("tv_chart");
  if(!container) return;
  container.innerHTML = "";
  const s = document.createElement("script");
  s.src = "https://s3.tradingview.com/external-embedding/embed-widget-advanced-chart.js";
  s.async = true;
  s.innerHTML = JSON.stringify({
    autosize: true,
    symbol: symbol,
    interval: "D",
    timezone: "Africa/Cairo",
    theme: "dark",
    style: "1",
    locale: "ar",
    allow_symbol_change: false,
    calendar: false,
    hide_top_toolbar: false,
    withdateranges: true,
    support_host: "https://www.tradingview.com"
  });
  container.appendChild(s);
}

window.setTVSymbol = function(ticker){
  const sym = ticker.startsWith("EGX:") ? ticker : ("EGX:" + ticker);
  renderTV(sym);
};

document.addEventListener("DOMContentLoaded", () => {
  renderTV(window.__tv_symbol);
});
