// l2split — frontend glue (TypeScript + Tailwind via Vite).
// Backend commands: crate l2split (src/gui.rs).
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { createIcons, icons } from "lucide";

type AdapterEntry = { name: string; label: string };
type NetInfo = {
  vpn: string;
  lan: string;
  adapters: AdapterEntry[];
  dhcp: boolean;
  ip: string;
  gw: string;
  mask: string;
  dns: string[];
  latency: string;
};
type Stats = { running: boolean; total: number; bypassed: number; vpn: number };
type AppRow = { name: string; path: string; icon: string; bypass: boolean; running?: boolean };

let isConnected = false;
let isTransitioning = false;
let appRows: AppRow[] = [];
let netCache: NetInfo | null = null;

const fmtInt = (n: number): string => (n || 0).toLocaleString("id-ID");

const byId = <T extends HTMLElement = HTMLElement>(id: string): T | null =>
  document.getElementById(id) as T | null;

function set(id: string, text: string): void {
  const el = byId(id);
  if (el) el.innerText = text;
}

function refreshIcons(): void {
  createIcons({ icons });
}

// ---------- tile (Pixel quick-settings) ----------
const kTileOn =
  "material-ripple w-full max-w-xs h-36 rounded-4xl bg-pixel-primaryContainer text-pixel-onPrimaryContainer p-6 flex flex-col justify-between transition-all duration-300 shadow-sm border border-pixel-primary/20 hover:brightness-105 active:scale-98 relative overflow-hidden group";
const kTileOff =
  "material-ripple w-full max-w-xs h-36 rounded-4xl bg-pixel-surface text-pixel-textSecondary p-6 flex flex-col justify-between transition-all duration-300 shadow-sm border border-pixel-surfaceHigh/60 hover:brightness-105 active:scale-98 relative overflow-hidden group";
const kIconOn =
  "w-12 h-12 rounded-2xl bg-pixel-primary text-pixel-onPrimary flex items-center justify-center shadow-sm transition-colors";
const kIconOff =
  "w-12 h-12 rounded-2xl bg-pixel-surfaceVariant text-pixel-textSecondary flex items-center justify-center shadow-sm";
const kBadgeOn =
  "text-xs font-semibold px-3 py-1 rounded-full bg-pixel-primary/20 text-pixel-primary border border-pixel-primary/30";
const kBadgeOff =
  "text-xs font-semibold px-3 py-1 rounded-full bg-pixel-surfaceVariant text-pixel-textSecondary border border-pixel-surfaceHigh";

function applyTile(): void {
  const tile = byId("warp-tile");
  const badge = byId("tile-badge");
  const iconC = byId("tile-icon-container");
  if (!tile || !badge || !iconC) return;
  tile.className = isConnected ? kTileOn : kTileOff;
  iconC.className = isConnected ? kIconOn : kIconOff;
  badge.className = isConnected ? kBadgeOn : kBadgeOff;
  badge.innerText = isConnected ? "TERHUBUNG" : "NONAKTIF";
  set("status-title", isConnected ? "Internet Terbypass" : "Bypass Nonaktif");
  set(
    "status-desc",
    isConnected ? "Bridge L2 LAN Mode (Bypass VPN)" : "Trafik melewati rute normal",
  );
  if (netCache) {
    set(
      "stat-proto",
      isConnected
        ? netCache.vpn === "None"
          ? "Tidak ada VPN"
          : netCache.vpn
        : "Tidak ada VPN",
    );
    set(
      "stat-colo",
      isConnected ? netCache.lan + " (Routed via VPN)" : netCache.lan + " (Direct)",
    );
  }
  refreshIcons();
}
// ---------- tab switch & bridge ----------
function switchTab(tabId: string): void {
  document.querySelectorAll(".tab-content").forEach((t) => t.classList.add("hidden"));
  document.querySelectorAll(".tab-btn").forEach((b) => {
    b.className =
      "tab-btn material-ripple w-full flex items-center gap-3.5 px-4 py-3 rounded-2xl text-xs font-medium text-pixel-textSecondary hover:bg-pixel-surfaceVariant/50";
  });
  const activeTab = byId(`tab-${tabId}`);
  const activeNav = byId(`nav-${tabId}`);
  activeTab?.classList.remove("hidden");
  if (activeNav) {
    activeNav.className =
      "tab-btn active material-ripple w-full flex items-center gap-3.5 px-4 py-3 rounded-2xl text-xs font-medium bg-pixel-primaryContainer text-pixel-onPrimaryContainer";
  }
}

function toggleBridge(): void {
  if (isTransitioning) return;
  isTransitioning = true;
  setTimeout(() => {
    isTransitioning = false;
  }, 300);
  void invoke(isConnected ? "stop" : "start");
}

// ---------- settings / IP ----------
function fillIpDetail(): void {
  if (!netCache) return;
  set("val-ip", netCache.ip || "Auto acquire");
  set("val-gateway", netCache.gw || "Auto acquire");
  set("val-subnet", netCache.mask || "Auto acquire");
  set("val-dns1", netCache.dns[0] || "Auto acquire");
  set("val-dns2", netCache.dns[1] || "Auto acquire");
  const sel = byId<HTMLSelectElement>("ip-mode-select");
  if (sel) sel.value = netCache.dhcp ? "DHCP" : "Static";
  applyModeUi(netCache.dhcp ? "DHCP" : "Static");
}

// mode Static -> tampilkan input editable; DHCP -> nilai bacaan
function applyModeUi(mode: string): void {
  const statik = mode === "Static";
  ["val-ip", "val-gateway", "val-subnet", "val-dns1", "val-dns2"].forEach((i) =>
    byId(i)?.classList.toggle("hidden", statik),
  );
  ["in-ip", "in-gw", "in-mask", "in-dns1", "in-dns2"].forEach((i) =>
    byId<HTMLInputElement>(i)?.classList.toggle("hidden", !statik),
  );
  if (statik && netCache) {
    const v = (id: string, val: string) => {
      const el = byId<HTMLInputElement>(id);
      if (el && !el.value) el.value = val;
    };
    v("in-ip", netCache.ip);
    v("in-gw", netCache.gw);
    v("in-mask", netCache.mask);
    v("in-dns1", netCache.dns[0] || "");
    v("in-dns2", netCache.dns[1] || "");
  }
}

function toggleIpMode(mode: string): void {
  if (mode === "Static") {
    if (netCache) applyModeUi("Static");
    else fillStaticPlaceholderEmpty();
  } else {
    applyModeUi("DHCP");
    fillIpDetail();
  }
}

function fillStaticPlaceholderEmpty(): void {
  applyModeUi("Static");
}

// ---------- toast ----------
function showToast(title: string, body: string): void {
  const t = byId("toast-notification");
  if (!t) return;
  const ps = t.querySelectorAll("p");
  if (ps[0]) ps[0].innerText = title;
  if (ps[1]) ps[1].innerText = body;
  t.classList.remove("opacity-0", "translate-y-4", "pointer-events-none");
  setTimeout(() => {
    t.classList.add("opacity-0", "translate-y-4", "pointer-events-none");
  }, 3000);
}

async function saveSettings(btn: HTMLButtonElement): Promise<void> {
  btn.disabled = true;
  btn.innerHTML = '<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i> Menyimpan...';
  refreshIcons();
  const sel = byId<HTMLSelectElement>("adapter-select");
  const modeSel = byId<HTMLSelectElement>("ip-mode-select");
  const val = (id: string): string => (byId<HTMLInputElement>(id)?.value ?? "").trim();
  try {
    if (sel) {
      const mode = modeSel ? modeSel.value : "DHCP";
      if (mode === "Static") {
        await invoke("apply_ip_config", {
          adapter: sel.value,
          mode: "Static",
          ip: val("in-ip"),
          gw: val("in-gw"),
          mask: val("in-mask"),
          dns1: val("in-dns1"),
          dns2: val("in-dns2"),
        });
      } else {
        await invoke("apply_ip_config", {
          adapter: sel.value,
          mode: "DHCP",
          ip: "", gw: "", mask: "", dns1: "", dns2: "",
        });
      }
      await invoke("set_to_adapter", { name: sel.value });
      netCache = null;
      applyNet(await invoke<NetInfo>("get_net"));
    }
  } catch (e) {
    showToast("Gagal Simpan", String(e));
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="save" class="w-4 h-4"></i> Simpan Pengaturan';
    refreshIcons();
    return;
  }
  setTimeout(() => {
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="save" class="w-4 h-4"></i> Simpan Pengaturan';
    refreshIcons();
    showToast("Pengaturan Tersimpan", "Konfigurasi L2 Bridge & IP telah diperbarui.");
  }, 600);
}
// ---------- apps ----------
function rowHtml(a: AppRow): string {
  const iconInner = a.icon
    ? `<img src="${a.icon}" class="w-6 h-6 object-contain">`
    : '<i data-lucide="file-code" class="w-5 h-5"></i>';
  const btnCls = a.bypass
    ? "text-pixel-onAccentGreen bg-pixel-accentGreen border border-pixel-accentGreen/50"
    : "text-pixel-textSecondary bg-pixel-surfaceVariant border border-pixel-surfaceHigh";
  const runBadge = a.running
    ? '<span class="text-[10px] px-2 py-0.5 rounded-full bg-pixel-accentGreen/10 text-pixel-accentGreen font-medium">Running</span>'
    : '<span class="text-[10px] px-2 py-0.5 rounded-full bg-pixel-surfaceVariant text-pixel-textSecondary font-medium">Terinstal</span>';
  return `
        <div class="bg-pixel-surface border border-pixel-surfaceHigh/40 p-3.5 rounded-3xl flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="w-9 h-9 rounded-2xl bg-pixel-surfaceVariant text-pixel-textSecondary flex items-center justify-center font-bold text-xs">${iconInner}</div>
                <div>
                    <div class="flex items-center gap-2">
                        <p class="text-xs font-bold text-pixel-textPrimary">${a.name}</p>
                        ${runBadge}
                    </div>
                    <p class="text-[11px] text-pixel-textSecondary font-mono mt-0.5 truncate max-w-xs">${a.path}</p>
                </div>
            </div>
            <button data-name="${a.name}" onclick="toggleRouting(this)" class="app-route-btn text-xs font-medium ${btnCls} px-3 py-1 rounded-full transition">${a.bypass ? "Bypass (LAN Direct)" : "VPN Tunnel"}</button>
        </div>`;
}

function renderApps(): void {
  const container = byId("apps-list-container");
  if (!container) return;
  container.innerHTML = appRows.map(rowHtml).join("");
  refreshIcons();
  updateAppCounts();
}

async function refreshApps(): Promise<void> {
  appRows = await invoke<AppRow[]>("list_apps");
  renderApps();
}
function toggleRouting(btn: HTMLElement): void {
  const name = btn.getAttribute("data-name");
  if (!name) return;
  const row = appRows.find((a) => a.name === name);
  if (!row) return;
  const on = !row.bypass;
  row.bypass = on;
  btn.innerText = on ? "Bypass (LAN Direct)" : "VPN Tunnel";
  btn.className =
    "app-route-btn text-xs font-medium " + (on
      ? "text-pixel-onAccentGreen bg-pixel-accentGreen border border-pixel-accentGreen/50"
      : "text-pixel-textSecondary bg-pixel-surfaceVariant border border-pixel-surfaceHigh") +
    " px-3 py-1 rounded-full transition";
  void invoke("set_bypass", { name, on });
  updateAppCounts();
  addLog(name, on);
}

function toggleAppRouting(btn: HTMLElement): void {
  toggleRouting(btn);
}

function updateAppCounts(): void {
  let bypassCount = 0;
  document.querySelectorAll<HTMLButtonElement>(".app-route-btn").forEach((btn) => {
    if (btn.innerText.includes("Bypass")) bypassCount++;
  });
  set("app-count-badge", `${bypassCount} Aktif`);
  set("active-process-count", `${appRows.length} Aplikasi • ${bypassCount} Aktif`);
  set("stat-apps-bridge-count", `${bypassCount} Aktif`);
}

// log fungsional: BYPASS/VPN mengikuti toggle + event bridge
function addLog(name: string, bypass: boolean): void {
  const viwan = netCache?.latency || "—";
  if (bypass) {
    pushLog(name, true, `Gateway: ${netCache?.gw || "direct"} • ${viwan}`);
  } else {
    pushLog(name, false, `Adapter: ${netCache?.vpn || "VPN"} • ${viwan}`);
  }
}

function pushLog(
  name: string,
  bypass: boolean,
  detail: string,
  label?: string,
): void {
  const lc = byId("log-list");
  if (!lc) return;
  const div = document.createElement("div");
  div.className = "flex items-center justify-between py-1.5 border-b border-pixel-surfaceHigh/30";
  const badge = label ?? (bypass ? "BYPASS LAN DIRECT" : "VPN TUNNEL");
  const dot = bypass ? "bg-pixel-accentGreen" : label ? "bg-pixel-textOutline" : "bg-pixel-primary";
  const bcls = bypass
    ? "bg-pixel-accentGreen/20 text-pixel-accentGreen"
    : label
      ? "bg-pixel-surfaceVariant text-pixel-textPrimary"
      : "bg-pixel-surfaceVariant text-pixel-textSecondary";
  div.innerHTML = `
        <div class="flex items-center gap-2">
            <span class="w-2 h-2 rounded-full ${dot}"></span>
            <span class="font-mono text-pixel-textPrimary font-semibold">${name}</span>
        </div>
        <div class="flex items-center gap-3">
            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full ${bcls}">${badge}</span>
            <span class="text-[11px] text-pixel-textSecondary font-mono">${detail}</span>
        </div>`;
  lc.prepend(div);
  while (lc.children.length > 30) lc.removeChild(lc.lastChild as ChildNode);
}

async function addAppPath(): Promise<void> {
  const input = byId<HTMLInputElement>("custom-app-path");
  if (!input) return;
  const p = (input.value || "").trim();
  if (!p) return;
  try {
    await invoke("add_app_path", { path: p });
    input.value = "";
    await refreshApps();
    addLog(p.split("\\").pop() || p, false);
  } catch (e) {
    showToast("Path tidak valid", String(e));
  }
}
// ---------- net ----------
function applyNet(n: NetInfo): void {
  netCache = n;
  set("stat-proto", n.vpn === "None" ? "Tidak ada VPN" : n.vpn);
  set("stat-colo", n.lan);
  set("stat-ip", n.ip || "—");
  set("stat-latency", n.latency || "—");
  set("stat-vpn-iface", n.vpn === "None" ? "Tanpa VPN (Direct)" : `${n.vpn} Interface`);
  set("stat-lan-iface", `${n.lan} (Direct)`);
  fillIpDetail();
  const sel = byId<HTMLSelectElement>("adapter-select");
  if (sel) {
    sel.innerHTML = n.adapters
      .map(
        (a) =>
          `<option value="${a.name}"${a.name === n.lan ? " selected" : ""}>${a.label}</option>`,
      )
      .join("");
  }
  applyTile();
}

// ---------- grafik throughput real ----------
type BarTick = { t: number; b: number };
const bars: BarTick[] = [];
let prevTotal = 0;
let prevBypassed = 0;

function drawBars(): void {
  const el = byId("chart-bars");
  if (!el) return;
  const max = Math.max(1, ...bars.map((x) => Math.max(x.t, x.b)));
  const now = bars.length;
  el.innerHTML = bars
    .map((x) => {
      const h1 = Math.max(2, Math.round((x.b / max) * 100));
      const h2 = Math.max(2, Math.round((x.t / max) * 100));
      const gap = now < 24 ? "flex-" + "grow" : "";
      return `<div class="flex h-full items-end w-full ${gap}" style="min-width:6px">
          <div class="w-full flex flex-col">
            <div class="w-full rounded-t bg-pixel-primary" style="height:${h2}%"></div>
            <div class="w-full rounded-b bg-pixel-accentGreen" style="height:${h1}%"></div>
          </div>
        </div>`;
    })
    .join("");
}

// ---------- boot ----------
window.addEventListener("error", (ev) => {
  try {
    showToast("JS Error", ev.message);
  } catch {
    /* noise */
  }
});

(async () => {
  refreshIcons();
  applyTile();

  // window chrome asli
  try {
    const win = getCurrentWindow();
    byId("btn-min")?.addEventListener("click", () => void win.minimize());
    byId("btn-max")?.addEventListener("click", () => void win.toggleMaximize());
    byId("btn-close")?.addEventListener("click", () => void win.close());
  } catch (e) {
    console.warn("chrome:", e);
  }

  set("app-count-badge", "0 Aktif");
  set("active-process-count", "Memuat aplikasi...");
  const ac = byId("apps-list-container");
  if (ac) {
    ac.innerHTML =
      '<p class="text-xs text-pixel-textSecondary py-4 text-center">Memuat daftar aplikasi...</p>';
  }
  set("stat-colo", "Memuat...");

  await listen<Stats>("stats", (e) => {
    const s = e.payload;
    const running = !!s.running;
    if (running && !isConnected) {
      pushLog(
        "Bridge",
        true,
        `${netCache?.vpn === "None" ? "tanpa VPN (fallback)" : netCache?.vpn || "VPN"} → ${netCache?.lan || "LAN"}`,
        "BRIDGE AKTIF",
      );
      prevTotal = 0;
      prevBypassed = 0;
      bars.length = 0;
    }
    if (!running && isConnected) {
      pushLog("Bridge", false, "Bridge berhenti", "BRIDGE BERHENTI");
    }
    isConnected = running;
    applyTile();

    // throughput: paksa seluruh delta per-detik (log stats 250ms)
    if (running) {
      const dTotal = s.total > prevTotal ? s.total - prevTotal : 0;
      const dBypass = s.bypassed > prevBypassed ? s.bypassed - prevBypassed : 0;
      prevTotal = s.total;
      prevBypassed = s.bypassed;
      bars.push({ t: dTotal, b: dBypass });
      if (bars.length > 24) bars.shift();
      drawBars();
    }
    set("stat-bypass", `${fmtInt(s.bypassed)} pkt`);
    set("stat-vpn", `${fmtInt(s.vpn)} pkt`);
  });
  await listen<boolean>("busy", (e) => {
    isTransitioning = !!e.payload;
    if (e.payload) {
      set("tile-badge", "MENYAMBUNG...");
    } else {
      applyTile();
    }
  });
  await listen<string>("failed", (e) => {
    showToast("Gagal", String(e.payload));
  });

  // ================= driver setup wizard =================
  void (async (): Promise<void> => {
    const ok = await invoke<boolean>("driver_check").catch(() => false);
    if (ok) return;
    const o = document.createElement("div");
    o.id = "driver-overlay";
    o.style.cssText =
      "position:fixed;inset:0;z-index:60;background:rgba(10,11,14,0.92);display:flex;align-items:center;justify-content:center";
    o.innerHTML = `
      <div class="w-[420px] rounded-3xl bg-pixel-surface border border-pixel-surfaceVariant/60 p-7">
        <div class="flex items-center gap-3 mb-4">
          <div class="w-10 h-10 rounded-2xl bg-pixel-primaryContainer flex items-center justify-center text-pixel-primary">
            <i data-lucide="plug-zap" class="w-5 h-5"></i>
          </div>
          <h2 class="font-bold text-sm text-pixel-textPrimary">Driver belum terpasang</h2>
        </div>
        <p class="text-xs text-pixel-textSecondary leading-relaxed mb-2">1. Tekan <b>Pasang driver</b>, setujui UAC (<b>Yes</b>).</p>
        <p class="text-xs text-pixel-textSecondary leading-relaxed mb-2">2. Kalau diminta restart dulu, restart lalu buka l2split lagi.</p>
        <div class="flex gap-3">
          <button id="drv-setup" class="flex-1 px-4 py-3 rounded-xl bg-pixel-primary text-pixel-onPrimary text-xs font-semibold">Pasang driver</button>
          <button id="drv-later" class="px-4 py-3 rounded-xl bg-pixel-surfaceVariant/50 text-pixel-textPrimary text-xs font-medium">Nanti</button>
        </div>
        <p id="drv-msg" class="text-[11px] text-pixel-textSecondary mt-4"></p>
      </div>`;
    document.body.appendChild(o);
    const msg = o.querySelector<HTMLElement>("#drv-msg");
    const setupBtn = o.querySelector<HTMLButtonElement>("#drv-setup");
    setupBtn?.addEventListener("click", () => {
      if (setupBtn) (setupBtn as HTMLButtonElement).disabled = true;
      void invoke<string>("driver_setup")
        .then((m) => {
          if (msg) msg.textContent = String(m);
          pushLog("Driver", true, "instalasi driver", String(m));
        })
        .catch((e) => {
          showToast("Gagal", String(e));
          if (msg) msg.textContent = String(e);
          if (setupBtn) (setupBtn as HTMLButtonElement).disabled = false;
        });
    });
    o.querySelector("#drv-later")?.addEventListener("click", () => o.remove());
  })();

  // Otomatis Hubungkan: autostart registry
  const cb = byId<HTMLInputElement>("auto-connect");
  if (cb) {
    const syncAuto = (v: boolean): void => {
      cb.checked = v;
      const l = byId("auto-label");
      if (l) l.innerText = v ? "Aktif" : "Nonaktif";
    };
    await invoke<boolean>("get_autostart")
      .then((v) => {
        syncAuto(v);
      })
      .catch(() => {});
    cb.addEventListener(
      "change",
      () => {
        invoke("set_autostart", { enabled: cb.checked })
          .then((msg) => {
            syncAuto(cb.checked);
            pushLog("Autostart", cb.checked, "registry HKCU Run", msg as string);
          })
          .catch((e) => showToast("Gagal", String(e)));
      },
    );
  }

  try {
    applyNet(await invoke<NetInfo>("get_net"));
  } catch (e) {
    console.warn("get_net:", e);
    set("stat-colo", "Driver tidak jalan");
  }
  try {
    await refreshApps();
  } catch (e) {
    console.warn("list_apps:", e);
  }

  const pollLatency = (): void => {
    void invoke<string>("get_latency")
      .then((v) => set("stat-latency", v))
      .catch(() => {});
  };
  pollLatency();
  setInterval(pollLatency, 10000);
})();

// handler inline markup (design pakai onclick=)
// shortcut keyboard: 1/2/3/4 = pindah tab
window.addEventListener("keydown", (ev) => {
  if (ev.target instanceof HTMLElement && (ev.target.tagName === "INPUT" || ev.target.tagName === "SELECT")) return;
  const map: Record<string, string> = { "1": "connection", "2": "analytics", "3": "apps", "4": "settings" };
  const t = map[ev.key];
  if (t) switchTab(t);
});

// default export glue
Object.assign(window as unknown as Record<string, unknown>, {
  switchTab,
  toggleBridge,
  toggleWarp: toggleBridge,
  toggleIpMode,
  toggleRouting,
  toggleAppRouting,
  addAppPath,
  saveSettings,
  updateAppCounts,
  fillIpDetail,
  applyModeUi,
  showToast,
  applyTile,
});
