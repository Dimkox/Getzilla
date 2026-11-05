#!/usr/bin/env node

import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const targetUrl = option("--url");
const outputOption = option("--output");
const suppliedCdp = option("--cdp-url");
const suppliedChrome = option("--chrome");
const cleanupPython = option("--cleanup-python") ?? (process.platform === "win32" ? "python" : "python3");
const cleanupHelper = fileURLToPath(new URL("./cleanup-owned-directory.py", import.meta.url));

if (!targetUrl || !outputOption) {
  console.error("Usage: node browser-contract.mjs --url <http-url> --output <directory> [--chrome <path> | --cdp-url <url>] [--cleanup-python <python>]");
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
const directoryCleanup = [];
let browserReport;
let cleanupPublished = false;

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

function cleanOwnedDirectory({ directory, identity }) {
  const expected = Object.fromEntries(["dev", "ino", "uid"].map((key) => [key, String(identity[key])]));
  const retained = (reason) => ({ schema_version: 1, directory, identity: expected,
    contents_cleaned: false, root_removed: false, path_state: "unknown", reason });
  return new Promise((resolve) => {
    let child, timer, finished = false, stdout = "", size = 0, refusal;
    const finish = (report) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve(report);
    };
    try {
      child = spawn(cleanupPython, ["-I", "-S", cleanupHelper, "--directory", directory,
        ...Object.entries(expected).flatMap(([key, value]) => [`--${key}`, value])],
      { stdio: ["ignore", "pipe", "ignore"], windowsHide: true });
    } catch { finish(retained("cleanup-helper-unavailable")); return; }
    child.once("error", () => { refusal = "cleanup-helper-unavailable"; });
    child.stdout.on("data", (chunk) => {
      size += chunk.length;
      if (size <= 4096) stdout += chunk.toString("utf8");
      else { refusal = "cleanup-helper-output-limit"; child.kill("SIGTERM"); }
    });
    child.once("close", (code) => {
      if (refusal || code !== 0) { finish(retained(refusal ?? "cleanup-helper-failed")); return; }
      try {
        const report = JSON.parse(stdout);
        const keys = ["schema_version", "directory", "identity", "contents_cleaned", "root_removed", "path_state", "reason"].sort();
        if (!report || Object.keys(report).sort().join() !== keys.join()
            || report.schema_version !== 1 || report.directory !== directory
            || !report.identity || Object.keys(report.identity).sort().join() !== "dev,ino,uid"
            || !Object.entries(expected).every(([key, value]) => report.identity[key] === value)
            || typeof report.contents_cleaned !== "boolean" || report.root_removed !== false
            || !["owned", "changed", "absent", "unknown"].includes(report.path_state)
            || typeof report.reason !== "string" || report.reason.length > 100
            || (report.contents_cleaned && report.reason !== "contents-cleaned-root-retained")) {
          throw new Error("invalid cleanup result");
        }
        finish(report);
      } catch { finish(retained("cleanup-helper-invalid-result")); }
    });
    timer = setTimeout(async () => {
      refusal = "cleanup-helper-timeout";
      child.kill("SIGTERM");
      if (!await waitForExit(child, 1000)) {
        child.kill("SIGKILL");
        await waitForExit(child, 1000);
      }
      finish(retained(refusal));
    }, 3000);
  });
}

function publishCleanup() {
  if (cleanupPublished) return;
  cleanupPublished = true;
  const directChild = !chromeProcess || chromeProcess.pid === undefined ? "not-owned"
    : chromeProcess.exitCode !== null || chromeProcess.signalCode !== null ? "reaped" : "running-or-unknown";
  const cleanup = { direct_child: directChild, directories: directoryCleanup };
  fs.writeFileSync(path.join(outputDir, "browser-cleanup.json"), `${JSON.stringify(cleanup, null, 2)}\n`);
  if (browserReport) {
    browserReport.cleanup = cleanup;
    fs.writeFileSync(path.join(outputDir, "browser-contract.json"), `${JSON.stringify(browserReport, null, 2)}\n`);
    console.log(JSON.stringify(browserReport, null, 2));
  }
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
      for (const owned of ownedDirectories.reverse()) {
        directoryCleanup.push(await cleanOwnedDirectory(owned));
      }
    }
  })();
  return chromeStopping;
}

const signalHandlers = new Map([["SIGINT", 130], ["SIGTERM", 143]].map(([signal, code]) => {
  const handler = () => {
    stopChrome().catch((error) => console.error(`Chrome cleanup failed: ${error.message}`))
      .finally(() => { publishCleanup(); process.exit(code); });
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
  browserReport = { url: targetUrl, viewports, keyboardFirstTab, passed };
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
    publishCleanup();
    for (const [signal, handler] of signalHandlers) process.off(signal, handler);
  }
}
