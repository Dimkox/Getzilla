#!/usr/bin/env node

import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const targetUrl = option("--url");
const outputOption = option("--output");
const suppliedCdp = option("--cdp-url");
const suppliedChrome = option("--chrome");

if (!targetUrl || !outputOption) {
  console.error("Usage: node browser-contract.mjs --url <http-url> --output <directory> [--chrome <path> | --cdp-url <url>]");
  process.exit(2);
}
const parsedTarget = new URL(targetUrl);
if (!['http:', 'https:'].includes(parsedTarget.protocol)) {
  throw new Error("--url must use http or https");
}

const outputDir = path.resolve(outputOption);
fs.mkdirSync(outputDir, { recursive: true });
let chromeProcess;
let chromeProfile;
let chromeRuntime;
let chromeDiagnostic = "";
let chromeStartupError;
let chromeStopping;
const ownedDirectories = [];

function privateDirectory(parent, prefix) {
  const directory = fs.mkdtempSync(path.join(parent, prefix));
  if (process.platform !== "win32") fs.chmodSync(directory, 0o700);
  const identity = fs.lstatSync(directory, { bigint: true });
  ownedDirectories.push({ directory, identity });
  return directory;
}

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

function findChrome() {
  const candidates = [suppliedChrome, process.env.CHROME_PATH, "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"].filter(Boolean);
  for (const candidate of candidates) {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {}
  }
  throw new Error("Chrome not found; pass --chrome or set CHROME_PATH");
}

async function launchChrome() {
  if (suppliedCdp) return suppliedCdp.replace(/\/$/, "");
  const port = await freePort();
  chromeProfile = privateDirectory(os.tmpdir(), "seo-landing-browser-contract-");
  // Chrome adds a singleton socket suffix. Inherited test paths can exceed AF_UNIX limits.
  chromeRuntime = privateDirectory(process.platform === "win32" ? os.tmpdir() : "/tmp", "gzc-");
  chromeProcess = spawn(findChrome(), [
    "--headless=new",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${chromeProfile}`,
    "about:blank",
  ], {
    stdio: ["ignore", "ignore", "pipe"],
    env: { ...process.env, TMPDIR: chromeRuntime, TEMP: chromeRuntime, TMP: chromeRuntime },
  });
  chromeProcess.stderr.on("data", (chunk) => {
    chromeDiagnostic = (chromeDiagnostic + chunk.toString("utf8")).slice(-4096);
  });
  chromeProcess.once("error", (error) => { chromeStartupError = error; });
  const cdpUrl = `http://127.0.0.1:${port}`;
  for (let attempt = 0; attempt < 450; attempt += 1) {
    if (chromeStartupError || chromeProcess.exitCode !== null || chromeProcess.signalCode !== null) {
      const reason = chromeStartupError?.message ?? chromeProcess.signalCode ?? chromeProcess.exitCode;
      throw new Error(`Chrome exited before startup: ${reason}\n${chromeDiagnostic}`);
    }
    try {
      const response = await fetch(`${cdpUrl}/json/version`);
      if (response.ok) return cdpUrl;
    } catch {}
    await delay(100);
  }
  throw new Error(`Timed out waiting for Chrome DevTools Protocol\n${chromeDiagnostic}`);
}

function waitForExit(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    let timer;
    const onExit = () => {
      clearTimeout(timer);
      child.off("exit", onExit);
      resolve(true);
    };
    child.once("exit", onExit);
    timer = setTimeout(() => {
      child.off("exit", onExit);
      resolve(false);
    }, timeoutMs);
    if (child.exitCode !== null || child.signalCode !== null) onExit();
  });
}

function stopChrome() {
  chromeStopping ??= (async () => {
    try {
      if (chromeProcess && chromeProcess.exitCode === null && chromeProcess.signalCode === null) {
        chromeProcess.kill("SIGTERM");
        if (!await waitForExit(chromeProcess, 3000)) {
          chromeProcess.kill("SIGKILL");
          if (!await waitForExit(chromeProcess, 3000)) throw new Error("Chrome did not exit after SIGKILL");
        }
      }
    } finally {
      const cleanupErrors = [];
      for (const { directory, identity } of ownedDirectories.reverse()) {
        try {
          let current;
          try { current = fs.lstatSync(directory, { bigint: true }); }
          catch (error) { if (error.code === "ENOENT") continue; throw error; }
          if (!current.isDirectory() || current.isSymbolicLink() || current.dev !== identity.dev
              || current.ino !== identity.ino || current.uid !== identity.uid) {
            throw new Error("Owned Chrome directory identity changed; refusing cleanup");
          }
          await fs.promises.rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        } catch (error) {
          cleanupErrors.push(error);
        }
      }
      if (cleanupErrors.length) throw new AggregateError(cleanupErrors, "Owned Chrome directory cleanup failed");
    }
  })();
  return chromeStopping;
}

const signalHandlers = new Map([["SIGINT", 130], ["SIGTERM", 143]].map(([signal, code]) => {
  const handler = () => {
    stopChrome().catch((error) => console.error(`Chrome cleanup failed: ${error.message}`))
      .finally(() => process.exit(code));
  };
  process.once(signal, handler);
  return [signal, handler];
}));
let primaryError;
try {
  const cdpUrl = await launchChrome();
  const pageResponse = await fetch(`${cdpUrl}/json/new?${encodeURIComponent(targetUrl)}`, { method: "PUT" });
  if (!pageResponse.ok) throw new Error(`Cannot create CDP page: HTTP ${pageResponse.status}`);
  const target = await pageResponse.json();
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });

  let nextId = 1;
  const pending = new Map();
  const eventWaiters = new Map();
  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const waiter = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) waiter.reject(new Error(JSON.stringify(message.error)));
      else waiter.resolve(message.result);
    } else if (message.method && eventWaiters.has(message.method)) {
      const resolve = eventWaiters.get(message.method);
      eventWaiters.delete(message.method);
      resolve(message.params);
    }
  });

  const command = (method, params = {}) => {
    const id = nextId++;
    socket.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
  };
  const waitForEvent = (method) => new Promise((resolve) => eventWaiters.set(method, resolve));
  const evaluate = async (expression) => {
    const result = await command("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };

  await command("Page.enable");
  await command("Runtime.enable");
  await command("Network.enable");
  await command("Network.setCacheDisabled", { cacheDisabled: true });
  await command("Emulation.setEmulatedMedia", {
    media: "screen",
    features: [{ name: "prefers-reduced-motion", value: "reduce" }],
  });

  const viewports = [];
  for (const width of [320, 768, 1280, 1920]) {
    await command("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 768 });
    const loaded = waitForEvent("Page.loadEventFired");
    await command("Page.navigate", { url: targetUrl });
    await loaded;
    const layout = await evaluate(`({
      width: innerWidth,
      documentWidth: document.documentElement.scrollWidth,
      bodyWidth: document.body.scrollWidth,
      overflow: document.documentElement.scrollWidth > innerWidth || document.body.scrollWidth > innerWidth,
      reducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches,
      scrollBehavior: getComputedStyle(document.documentElement).scrollBehavior
    })`);
    const screenshot = await command("Page.captureScreenshot", { format: "png", fromSurface: true, captureBeyondViewport: false });
    fs.writeFileSync(path.join(outputDir, `viewport-${width}.png`), Buffer.from(screenshot.data, "base64"));
    viewports.push(layout);
  }

  await command("Emulation.setDeviceMetricsOverride", { width: 320, height: 900, deviceScaleFactor: 1, mobile: true });
  const loaded = waitForEvent("Page.loadEventFired");
  await command("Page.navigate", { url: targetUrl });
  await loaded;
  await command("Input.dispatchKeyEvent", { type: "rawKeyDown", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 });
  await command("Input.dispatchKeyEvent", { type: "keyUp", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 });
  const keyboardFirstTab = await evaluate(`(() => {
    const element = document.activeElement;
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return {
      tag: element.tagName,
      className: element.className,
      href: element.getAttribute('href'),
      visible: rect.bottom > 0 && rect.top < innerHeight,
      outlineStyle: style.outlineStyle,
      outlineWidth: style.outlineWidth
    };
  })()`);

  const passed = viewports.every((item) => !item.overflow && item.reducedMotion && item.scrollBehavior === "auto")
    && keyboardFirstTab.className.includes("skip-link")
    && keyboardFirstTab.href === "#content"
    && keyboardFirstTab.visible
    && keyboardFirstTab.outlineStyle !== "none"
    && Number.parseFloat(keyboardFirstTab.outlineWidth) >= 2;
  const report = { url: targetUrl, viewports, keyboardFirstTab, passed };
  fs.writeFileSync(path.join(outputDir, "browser-contract.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
  socket.close();
  if (!passed) process.exitCode = 1;
} catch (error) {
  primaryError = error;
  throw error;
} finally {
  try { await stopChrome(); }
  catch (error) {
    if (!primaryError) throw error;
    console.error(`Chrome cleanup failed: ${error.message}`);
  } finally {
    for (const [signal, handler] of signalHandlers) process.off(signal, handler);
  }
}
