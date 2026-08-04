import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
);

// Registered after load so it never competes with the app shell for the initial paint. Swallowed
// on failure -- unsupported browser, or served over plain HTTP where the Service Worker API is
// unavailable outside localhost -- since offline caching is a nice-to-have, not a requirement to
// use HomeAtlas.
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  });
}
