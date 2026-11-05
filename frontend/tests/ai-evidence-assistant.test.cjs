"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const APP_PATH = path.resolve(__dirname, "..", "app.js");
const APP_SOURCE = fs.readFileSync(APP_PATH, "utf8");
const INDEX_PATH = path.resolve(__dirname, "..", "index.html");
const INDEX_SOURCE = fs.readFileSync(INDEX_PATH, "utf8");
const INDEX_ELEMENT_IDS = new Set(
  [...INDEX_SOURCE.matchAll(/\bid=["']([^"']+)["']/g)].map((match) => match[1])
);
const CAPABILITY_PATH = path.resolve(__dirname, "..", "..", "src-tauri", "capabilities", "default.json");

class FakeClassList {
  constructor(element) {
    this.element = element;
  }

  add(...names) {
    names.forEach((name) => this.element._classes.add(name));
  }

  remove(...names) {
    names.forEach((name) => this.element._classes.delete(name));
  }

  contains(name) {
    return this.element._classes.has(name);
  }

  toggle(name, force) {
    if (force === true) {
      this.add(name);
      return true;
    }
    if (force === false) {
      this.remove(name);
      return false;
    }
    if (this.contains(name)) {
      this.remove(name);
      return false;
    }
    this.add(name);
    return true;
  }
}

class FakeElement {
  constructor(tagName = "div", id = "") {
    this.tagName = tagName.toUpperCase();
    this.id = id;
    this._classes = new Set();
    this.classList = new FakeClassList(this);
    this._innerHTML = "";
    this.textContent = "";
    this.value = "";
    this.disabled = false;
    this.open = false;
    this.title = "";
    this.style = {};
    this.dataset = {};
    this.attributes = new Map();
    this.children = [];
    this.parentElement = null;
    this.isConnected = true;
    this.listeners = new Map();
    if (this.tagName === "TEMPLATE") {
      this.content = new FakeElement("fragment");
    }
  }

  get className() {
    return [...this._classes].join(" ");
  }

  set className(value) {
    this._classes = new Set(String(value || "").split(/\s+/).filter(Boolean));
  }

  get innerHTML() {
    return this._innerHTML;
  }

  set innerHTML(value) {
    this._innerHTML = String(value);
    this.children = [];
  }

  get firstElementChild() {
    return this.children[0] || null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  getAttribute(name) {
    return this.attributes.get(name) || null;
  }

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) || [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  dispatchEvent(event) {
    event.target = event.target || this;
    for (const listener of this.listeners.get(event.type) || []) {
      listener.call(this, event);
    }
    return true;
  }

  click() {
    this.dispatchEvent({ type: "click" });
  }

  focus() {
    this.dispatchEvent({ type: "focus" });
  }

  appendChild(child) {
    if (child == null) return child;
    child.parentElement = this;
    child.isConnected = this.isConnected;
    this.children.push(child);
    return child;
  }

  append(...children) {
    children.forEach((child) => this.appendChild(child));
  }

  cloneNode(deep = false) {
    const clone = new FakeElement(this.tagName, this.id);
    clone.className = this.className;
    clone.textContent = this.textContent;
    clone.value = this.value;
    clone.disabled = this.disabled;
    clone._innerHTML = this._innerHTML;
    if (deep) this.children.forEach((child) => clone.appendChild(child.cloneNode(true)));
    return clone;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }

  querySelectorAll(selector) {
    const matches = [];
    const visit = (element) => {
      for (const child of element.children) {
        const matchesClass = selector.startsWith(".") && child.classList.contains(selector.slice(1));
        const matchesId = selector.startsWith("#") && child.id === selector.slice(1);
        const matchesTag = !selector.startsWith(".") && !selector.startsWith("#") &&
          child.tagName.toLowerCase() === selector.toLowerCase();
        if (matchesClass || matchesId || matchesTag) matches.push(child);
        visit(child);
      }
    };
    visit(this);
    return matches;
  }
}

class FakeDocument {
  constructor(allowedIds = null) {
    this.elements = new Map();
    this.allowedIds = allowedIds;
  }

  getElementById(id) {
    if (this.allowedIds && !this.allowedIds.has(id)) return null;
    if (!this.elements.has(id)) {
      const tagName = id.endsWith("-select") ? "select" : (id.endsWith("-input") || id.endsWith("-box") ? "input" : (id.endsWith("-btn") ? "button" : "div"));
      this.elements.set(id, new FakeElement(tagName, id));
    }
    return this.elements.get(id);
  }

  createElement(tagName) {
    return new FakeElement(tagName);
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }

  querySelectorAll(selector) {
    const matches = [];
    for (const el of this.elements.values()) {
      matches.push(...el.querySelectorAll(selector));
    }
    return matches;
  }

  addEventListener() {}
  removeEventListener() {}
}

class FakeStorage {
  constructor() {
    this.store = new Map();
  }
  getItem(k) {
    return this.store.has(k) ? this.store.get(k) : null;
  }
  setItem(k, v) {
    this.store.set(k, String(v));
  }
  removeItem(k) {
    this.store.delete(k);
  }
  clear() {
    this.store.clear();
  }
}

class FakeTabulatorColumn {
  constructor(field, visible = true) {
    this.field = field;
    this.visible = visible;
  }
  getField() { return this.field; }
  isVisible() { return this.visible; }
}

class FakeTabulator {
  constructor(_selector, options) {
    this.options = options;
    this.data = [...(options.data || [])];
    this.columns = (options.columns || []).map((col) => new FakeTabulatorColumn(col.field, col.visible !== false));
    this.listeners = new Map();
    FakeTabulator.latest = this;
  }
  on(eventName, listener) {
    this.listeners.set(eventName, listener);
  }
  getColumns() {
    return this.columns;
  }
  getSelectedData() {
    return this.data.slice(0, 2);
  }
  getSelectedRows() {
    return this.data.slice(0, 2).map((d) => ({
      getData: () => d,
      getElement: () => null,
    }));
  }
  getRows() {
    return this.data.map((d) => ({
      getData: () => d,
      getElement: () => null,
    }));
  }
  replaceData(d) {
    this.data = [...d];
  }
  redraw() {}
  destroy() {}
}

function bootAssistantTestApp({ fetchHandler, invokeHandler, confirmResult = true, initialKey = "", initialModel = "gemini-2.5-flash", strictDom = false } = {}) {
  FakeTabulator.latest = null;
  const fetchCalls = [];
  const tauriCalls = [];
  const initializationErrors = [];
  const document = new FakeDocument(strictDom ? INDEX_ELEMENT_IDS : null);
  const localStorage = new FakeStorage();
  const sessionStorage = new FakeStorage();

  if (initialKey) {
    sessionStorage.setItem("logparser_gemini_api_key", initialKey);
  }
  if (initialModel) {
    localStorage.setItem("logparser_gemini_model", initialModel);
  }

  const mockFetch = async (url, options = {}) => {
    fetchCalls.push({ url, options });
    if (fetchHandler) {
      return fetchHandler(url, options);
    }
    // Default 200 OK response for ping/generateContent
    return {
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () => ({
        candidates: [
          {
            content: {
              parts: [{ text: "### 1. Observed Evidence\nObserved logon activity [evidence.csv | row #1].\n\n### 2. Inferences\nSuspicious activity [Confidence: High] [evidence.csv | row #1].\n\n### 3. Unknowns / Gaps\nUnknown parent process.\n\n### 4. Suggested Next Hunts\nHunt for event ID 4688." }],
            },
          },
        ],
      }),
      text: async () => "OK",
    };
  };

  const window = {
    __TAURI__: {
      core: {
        invoke: async (command, args) => {
          tauriCalls.push({ command, args });
          if (invokeHandler) {
            const handled = await invokeHandler(command, args);
            if (handled !== undefined) return handled;
          }
          if (command === "plugin:dialog|message") {
            const confirmed = await Promise.resolve(confirmResult);
            return confirmed ? "Ok" : "Cancel";
          }
          if (command === "gemini_test_connection") {
            return { model: args.request.model, verified: true };
          }
          if (command === "gemini_generate") {
            return {
              model: args.request.model,
              text: "### 1. Observed Evidence\nObserved logon activity [evidence.csv | row #1].\n\n### 2. Inferences\nSuspicious activity [Confidence: High] [evidence.csv | row #1].\n\n### 3. Unknowns / Gaps\nUnknown parent process.\n\n### 4. Suggested Next Hunts\nHunt for event ID 4688.",
            };
          }
          if (command === "gemini_list_models") {
            return [{ id: "gemini-2.5-flash", displayName: "Gemini 2.5 Flash" }];
          }
          if (command === "parse_guided_query") {
            return {
              accepted: true,
              plan: {
                auditId: 1,
                intentToken: '{"intent":"filter"}',
                querySpec: { filters: [] },
              },
            };
          }
          if (command === "run_guided_query") {
            return { rows: [{ row_num: 1, commandline: "powershell.exe" }], hasMore: false };
          }
          if (command === "local_ai_runtime_status") {
            return { status: "ready", modelName: "gpt-oss-20b", installed: true };
          }
          if (command === "local_ai_analyze_evidence") {
            return {
              text: "### 1. Observed Evidence\nObserved activity [security.evtx | row #1].\n\n### 2. Inferences\nHigh confidence finding [Confidence: High] [security.evtx | row #1].\n\n### 3. Unknowns / Gaps\nNone observed.\n\n### 4. Suggested Next Hunts\nHunt 4688.",
              historyText: "### 1. Observed Evidence\nObserved activity [E1].\n\n### 2. Inferences\nHigh confidence finding [Confidence: High] [E1].\n\n### 3. Unknowns / Gaps\nNone observed.\n\n### 4. Suggested Next Hunts\nHunt 4688.",
              provider: "local-llama-cpp",
              model: "gpt-oss-20b",
              modelVersion: "MXFP4@ggml-org",
              citations: [{ evidenceId: "E1", file: "security.evtx", rowNumber: 1, verified: true }],
            };
          }
          return null;
        },
      },
      event: { listen: async () => () => {} },
    },
    __logParserDebug: {},
    confirm: () => confirmResult,
    addEventListener: () => {},
    removeEventListener: () => {},
    requestAnimationFrame: (cb) => setTimeout(cb, 0),
    cancelAnimationFrame: (id) => clearTimeout(id),
    fetch: mockFetch,
    localStorage,
    sessionStorage,
  };
  window.window = window;

  const sandbox = {
    window,
    document,
    Tabulator: FakeTabulator,
    localStorage,
    sessionStorage,
    fetch: mockFetch,
    alert: (msg) => { sandbox.lastAlert = msg; },
    lastAlert: null,
    console: {
      error: (...args) => { initializationErrors.push(args); },
      warn: () => {},
      log: () => {},
    },
    setTimeout,
    clearTimeout,
    requestAnimationFrame: (cb) => setTimeout(cb, 0),
    cancelAnimationFrame: (id) => clearTimeout(id),
  };

  vm.runInNewContext(APP_SOURCE, sandbox, { filename: APP_PATH });

  return {
    document,
    debug: window.__logParserDebug,
    fetchCalls,
    tauriCalls,
    sandbox,
    localStorage,
    sessionStorage,
    initializationErrors,
  };
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

test("1. The exact selected/custom Gemini model ID is used for both Test and Send", async () => {
  const app = bootAssistantTestApp({ initialKey: "AIzaSyTestKey12345" });

  // Default selection is gemini-2.5-flash
  assert.equal(app.debug.getResolvedGeminiModelForTest(), "gemini-2.5-flash");

  // Run test
  await app.debug.testGeminiModelForTest();
  let cloudCalls = app.tauriCalls.filter((call) => call.command === "gemini_test_connection");
  assert.equal(cloudCalls.length, 1);
  assert.equal(cloudCalls[0].args.request.model, "gemini-2.5-flash");
  assert.equal(app.fetchCalls.length, 0, "The webview must never contact Gemini directly");

  // Stage a row and Send
  app.debug.stageAiEvidenceForTest([
    { row_num: 1, fileName: "security.evtx", EventID: 4624, User: "admin", timestamp: "2026-03-31 10:00:00" },
  ]);
  await app.debug.sendGeminiAnalysisForTest("Explain activity");
  cloudCalls = app.tauriCalls.filter((call) => call.command === "gemini_generate");
  assert.equal(cloudCalls.length, 1);
  assert.equal(cloudCalls[0].args.request.model, "gemini-2.5-flash");

  // Now set custom model: "gemini-custom-dfir-pro"
  const customInput = app.document.getElementById("gemini-custom-model-input");
  customInput.value = "gemini-custom-dfir-pro";
  assert.equal(app.debug.getResolvedGeminiModelForTest(), "gemini-custom-dfir-pro");

  await app.debug.testGeminiModelForTest();
  cloudCalls = app.tauriCalls.filter((call) => call.command === "gemini_test_connection");
  assert.equal(cloudCalls.length, 2);
  assert.equal(cloudCalls[1].args.request.model, "gemini-custom-dfir-pro");

  await app.debug.sendGeminiAnalysisForTest("Analyze custom");
  cloudCalls = app.tauriCalls.filter((call) => call.command === "gemini_generate");
  assert.equal(cloudCalls.length, 2);
  assert.equal(cloudCalls[1].args.request.model, "gemini-custom-dfir-pro");
  assert.equal(app.fetchCalls.length, 0);
});

test("2. A key string alone never produces Verified/Connected state", async () => {
  const app = bootAssistantTestApp();

  // Initially empty
  let ver = app.debug.getGeminiVerificationState();
  assert.equal(ver.status, "offline");

  // User enters key into Settings input
  const keyInput = app.document.getElementById("gemini-api-key-input");
  keyInput.value = "AIzaSyMyPersonalKey999";
  keyInput.dispatchEvent({ type: "input" });

  ver = app.debug.getGeminiVerificationState();
  assert.notEqual(ver.status, "verified");
  assert.notEqual(ver.status, "connected");
  assert.equal(ver.status, "unverified");

  const statusText = app.document.getElementById("gemini-status-text").textContent;
  assert.doesNotMatch(statusText, /Connected/i);
  assert.match(statusText, /Unverified/i);
});

test("3. Key/model changes invalidate verification", async () => {
  const app = bootAssistantTestApp({ initialKey: "AIzaSyValidKey456" });

  // Test and verify
  await app.debug.testGeminiModelForTest();
  let ver = app.debug.getGeminiVerificationState();
  assert.equal(ver.status, "verified");

  // Change model in select
  const modelSelect = app.document.getElementById("gemini-model-select");
  modelSelect.value = "gemini-2.5-pro";
  modelSelect.dispatchEvent({ type: "change" });

  ver = app.debug.getGeminiVerificationState();
  assert.equal(ver.status, "unverified", "Verification must be invalidated immediately when model changes");

  // Re-verify for gemini-2.5-pro
  await app.debug.testGeminiModelForTest();
  ver = app.debug.getGeminiVerificationState();
  assert.equal(ver.status, "verified");

  // Change API key input
  const keyInput = app.document.getElementById("gemini-api-key-input");
  keyInput.value = "AIzaSyNewDifferentKey789";
  keyInput.dispatchEvent({ type: "input" });

  ver = app.debug.getGeminiVerificationState();
  assert.equal(ver.status, "unverified", "Verification must be invalidated immediately when key changes");
});

test("4. Opening the assistant, selecting rows, staging rows, or opening preview makes no network request", async () => {
  const app = bootAssistantTestApp({ initialKey: "AIzaSyKey123" });
  assert.equal(app.fetchCalls.length, 0);

  // 1. Stage rows
  const staged = app.debug.stageAiEvidenceForTest([
    { row_num: 10, fileName: "sysmon.csv", Image: "svchost.exe", CommandLine: "svchost.exe -k netsvcs" },
    { row_num: 11, fileName: "sysmon.csv", Image: "powershell.exe", CommandLine: "powershell.exe -enc AAAA" },
  ]);
  assert.equal(staged, true);
  assert.equal(app.fetchCalls.length, 0, "Staging rows must not make network requests");

  // 2. Open payload preview button
  const previewBtn = app.document.getElementById("ai-preview-payload-btn");
  if (previewBtn) previewBtn.click();
  assert.equal(app.fetchCalls.length, 0, "Opening preview modal must not make network requests");

  // 3. Clear staged
  app.debug.clearStagedAiEvidenceForTest();
  assert.equal(app.fetchCalls.length, 0, "Clearing staged rows must not make network requests");
});

test("5. A backend cloud request occurs only after explicit Send and confirmation", async () => {
  const app = bootAssistantTestApp({ initialKey: "AIzaSyKey123" });
  assert.equal(app.fetchCalls.length, 0);

  // Stage evidence
  app.debug.stageAiEvidenceForTest([
    { row_num: 1, fileName: "auth.log", message: "Failed password for root" },
  ]);
  assert.equal(app.fetchCalls.length, 0);

  // Explicit Send
  await app.debug.sendGeminiAnalysisForTest("Analyze auth failure");
  const cloudCalls = app.tauriCalls.filter((call) => call.command === "gemini_generate");
  assert.equal(cloudCalls.length, 1, "Only explicit Send triggers the backend Gemini command");
  assert.equal(app.fetchCalls.length, 0, "The webview must never contact Gemini directly");
});

test("6. Payload includes selected headers and provenance (file/sheet/row) for each evidence row", async () => {
  const app = bootAssistantTestApp({ initialKey: "AIzaSyKey123" });

  app.debug.stageAiEvidenceForTest([
    {
      row_num: 42,
      fileName: "Security_Events.xlsx",
      sheet: "LogonEvents",
      utcText: "2026-03-31 12:30:00 UTC",
      User: "alice",
      Action: "Logon",
    },
  ]);

  const state = app.debug.getAiAssistantState();
  assert.ok(state.stagedEvidence, "Staged evidence should be stored");
  assert.equal(state.stagedEvidence.rows.length, 1);

  const row = state.stagedEvidence.rows[0];
  assert.ok(row._provenance, "Row must include _provenance");
  assert.equal(row._provenance.file, "Security_Events.xlsx");
  assert.equal(row._provenance.sheet, "LogonEvents");
  assert.equal(row._provenance.rowNumber, 42);
  assert.equal(row._provenance.timestamp, "2026-03-31 12:30:00 UTC");
  assert.equal(row.User, "alice");
  assert.equal(row.Action, "Logon");

  // Check serialized JSON contains headers and provenance
  const json = JSON.parse(state.stagedEvidence.payloadJson);
  assert.deepEqual(json.scope.files, ["Security_Events.xlsx"]);
  assert.equal(json.scope.totalRows, 1);
  assert.ok(json.evidence[0]._provenance);
});

test("7. Large selections become a complete AI row scope and are not silently truncated", async () => {
  const app = bootAssistantTestApp({ initialKey: "AIzaSyKey123" });
  const limits = app.debug.getAiEvidenceLimits();

  // Test row count limit > 250
  const oversizedRows = [];
  for (let i = 1; i <= limits.MAX_ROWS + 1; i++) {
    oversizedRows.push({ row_num: i, fileName: "big.csv", col: `val_${i}` });
  }

  const stagedResult = app.debug.stageAiEvidenceForTest(oversizedRows);
  assert.equal(stagedResult, true, "Large selections must become an explicit AI row scope");
  const scoped = app.debug.getAiAssistantState();
  assert.equal(scoped.stagedEvidence, null);
  assert.equal(scoped.selectionScope.rows.length, oversizedRows.length);
  assert.equal(app.fetchCalls.length, 0, "Creating a row scope makes no network request");

  // Test column count limit > 60
  const rowWithManyCols = { row_num: 1, fileName: "wide.csv" };
  for (let c = 1; c <= limits.MAX_COLUMNS + 5; c++) {
    rowWithManyCols[`field_${c}`] = `val_${c}`;
  }
  const colStagedResult = app.debug.stageAiEvidenceForTest([rowWithManyCols]);
  assert.equal(colStagedResult, false, "Oversized column count must be rejected");
  assert.match(app.sandbox.lastAlert, /exceeding the per-chunk limit of 60/);

  // Test Master Timeline narrative limit > 100 events
  const oversizedTimeline = [];
  for (let i = 1; i <= limits.MAX_TIMELINE_NARRATIVE_ROWS + 10; i++) {
    oversizedTimeline.push({ row_num: i, fileName: "timeline.csv", action: "test" });
  }
  await app.debug.generateIncidentNarrativeWithGeminiForTest(oversizedTimeline, ["198.51.100.1"]);
  assert.equal(app.fetchCalls.length, 0, "Must not call Gemini when timeline exceeds 100 events");
  const narrativeBody = app.document.getElementById("gemini-narrative-body").innerHTML;
  assert.match(narrativeBody, /Timeline Exceeds AI Analysis Limit/i);
});

test("8. No request or error output exposes the API key", async () => {
  const secretKey = "AIzaSySuperSecretKey1234567890123456";
  const app = bootAssistantTestApp({
    initialKey: secretKey,
    invokeHandler: async (command) => {
      if (command === "gemini_test_connection") {
        throw new Error(`Permission denied for key=${secretKey}`);
      }
      return undefined;
    },
  });

  // Test sanitized error helper directly
  const sanitized = app.debug.sanitizeErrorMessageForTest(
    `Failed request to https://api.com?key=${secretKey}&other=1 with key=${secretKey}`,
    secretKey
  );
  assert.doesNotMatch(sanitized, new RegExp(secretKey));
  assert.match(sanitized, /\[REDACTED/);

  // Test live model test failure
  await app.debug.testGeminiModelForTest();
  const ver = app.debug.getGeminiVerificationState();
  assert.equal(ver.status, "failed");
  assert.doesNotMatch(ver.errorMessage, new RegExp(secretKey));

  const statusText = app.document.getElementById("gemini-status-text").textContent;
  assert.doesNotMatch(statusText, new RegExp(secretKey));
});

test("9. Local Find Evidence still uses the offline path and performs no Gemini request", async () => {
  const app = bootAssistantTestApp({ initialKey: "AIzaSyKey123" });

  // Execute offline search
  await app.debug.searchAiEvidenceForTest("find powershell activity");

  // Check that parse_guided_query was invoked via Tauri
  const tauriCommands = app.tauriCalls.map((c) => c.command);
  assert.ok(tauriCommands.includes("parse_guided_query"), "Must invoke parse_guided_query");

  // Check that zero Gemini requests were made
  assert.equal(app.fetchCalls.length, 0, "Local search must never call Gemini API");
});

test("10. General Gemini analysis no longer routes through deterministic ask_analyst template prose", async () => {
  const app = bootAssistantTestApp({ initialKey: "AIzaSyKey123" });

  app.debug.stageAiEvidenceForTest([
    { row_num: 1, fileName: "test.csv", commandline: "whoami" },
  ]);

  await app.debug.sendGeminiAnalysisForTest("Analyze whoami execution");

  // Verify the backend Gemini command receives the structured prompt
  assert.equal(app.fetchCalls.length, 0);
  const generateCall = app.tauriCalls.find((call) => call.command === "gemini_generate");
  assert.ok(generateCall, "Gemini analysis must route through the Rust backend");
  const userText = generateCall.args.request.prompt;
  assert.match(userText, /Structured Staged Evidence/);
  assert.match(userText, /Analyze whoami execution/);

  // Ensure ask_analyst Tauri command was NOT called
  const tauriCommands = app.tauriCalls.map((c) => c.command);
  assert.ok(!tauriCommands.includes("ask_analyst"), "Must not route through ask_analyst template prose");
});

test("11. The old first-80-events silent sampling behavior is gone", async () => {
  let capturedTimelinePrompt = "";
  const app = bootAssistantTestApp({
    initialKey: "AIzaSyKey123",
    invokeHandler: async (command, args) => {
      if (command !== "gemini_generate") return undefined;
      capturedTimelinePrompt = args.request.prompt;
      return {
        model: args.request.model,
        text: "### 1. Executive Summary\nAnalyzed all events.",
      };
    },
  });

  // Provide exactly 50 timeline events
  const fiftyEvents = [];
  for (let i = 1; i <= 50; i++) {
    fiftyEvents.push({
      fileName: `evidence_${i % 3}.csv`,
      utcText: `2026-03-31 10:${String(i).padStart(2, "0")}:00 UTC`,
      user: `user_${i}`,
      action: "ProcessCreate",
      details: `cmd.exe /c step_${i}`,
    });
  }

  await app.debug.generateIncidentNarrativeWithGeminiForTest(fiftyEvents, ["user_1"]);

  assert.equal(app.fetchCalls.length, 0);
  assert.equal(app.tauriCalls.filter((call) => call.command === "gemini_generate").length, 1);
  // Verify all 50 events are present in the prompt, not sliced to 80 or any subset
  assert.match(capturedTimelinePrompt, /Event Count: 50/);
  assert.match(capturedTimelinePrompt, /step_50/);

  const subtitle = app.document.getElementById("gemini-narrative-subtitle").textContent;
  assert.match(subtitle, /Analyzed complete set of 50 timeline events/);
});

test("12. Missing source row numbers stay null and are never fabricated from array position", () => {
  const app = bootAssistantTestApp({ initialKey: "AIzaSyKey123" });

  app.debug.stageAiEvidenceForTest([
    { fileName: "unknown_rows.csv", _unifiedIndex: 77, message: "first" },
    { fileName: "unknown_rows.csv", message: "second" },
  ]);

  const payload = JSON.parse(app.debug.getAiAssistantState().stagedEvidence.payloadJson);
  assert.equal(payload.evidence[0]._provenance.rowNumber, null);
  assert.equal(payload.evidence[1]._provenance.rowNumber, null);
  assert.equal(payload.evidence[0]._provenance.status, "missing-row-number");
  assert.notEqual(payload.evidence[0]._provenance.rowNumber, 77);
  assert.notEqual(payload.evidence[1]._provenance.rowNumber, 2);
});

test("13. Gemini API keys are session-only and never written to localStorage", () => {
  const app = bootAssistantTestApp();
  const keyInput = app.document.getElementById("gemini-api-key-input");
  keyInput.value = "AIzaSySessionOnlyKey";
  app.document.getElementById("settings-save-btn").click();

  assert.equal(app.sessionStorage.getItem("logparser_gemini_api_key"), "AIzaSySessionOnlyKey");
  assert.equal(app.localStorage.getItem("logparser_gemini_api_key"), null);
});

test("14. Declining the cloud transfer confirmation prevents the backend request", async () => {
  const app = bootAssistantTestApp({ initialKey: "AIzaSyKey123", confirmResult: false });
  app.debug.stageAiEvidenceForTest([
    { row_num: 1, fileName: "auth.log", message: "Failed password" },
  ]);

  await app.debug.sendGeminiAnalysisForTest("Analyze auth failure");
  assert.equal(app.tauriCalls.filter((call) => call.command === "gemini_generate").length, 0);
  assert.equal(app.fetchCalls.length, 0);
});

test("15. Local gpt-oss download is never started by opening or initializing settings", () => {
  const app = bootAssistantTestApp();
  app.document.getElementById("settings-btn").click();

  assert.equal(
    app.tauriCalls.filter((call) => call.command === "local_ai_download_model").length,
    0
  );
  assert.ok(
    app.tauriCalls.some((call) => call.command === "local_ai_model_status"),
    "settings may query local installation status without downloading"
  );
});

test("16. Local gpt-oss download requires the examiner's explicit confirmation", async () => {
  const declined = bootAssistantTestApp({ confirmResult: false });
  declined.document.getElementById("local-ai-download-btn").click();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(
    declined.tauriCalls.filter((call) => call.command === "local_ai_download_model").length,
    0
  );

  const accepted = bootAssistantTestApp({ confirmResult: true });
  accepted.document.getElementById("local-ai-download-btn").click();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(
    accepted.tauriCalls.filter((call) => call.command === "local_ai_download_model").length,
    1
  );
});

test("17. Local analysis uses local_ai_analyze_evidence, causes zero Gemini requests, and has no cloud modal", async () => {
  const app = bootAssistantTestApp({ confirmResult: false }); // confirmResult false would block Gemini
  app.debug.setAiProviderForTest("local");

  app.debug.stageAiEvidenceForTest([
    { row_num: 1, fileName: "security.evtx", EventID: 4624, User: "alice" },
  ]);

  await app.debug.sendLocalAiAnalysisForTest("Explain local activity");

  // Zero cloud requests made
  assert.equal(app.fetchCalls.length, 0, "Local analysis must never call cloud fetch");
  const cloudCalls = app.tauriCalls.filter((c) => c.command === "gemini_generate");
  assert.equal(cloudCalls.length, 0, "Zero gemini_generate calls");

  // local_ai_analyze_evidence was invoked
  const localCalls = app.tauriCalls.filter((c) => c.command === "local_ai_analyze_evidence");
  assert.equal(localCalls.length, 1, "Must invoke local_ai_analyze_evidence");
  assert.equal(localCalls[0].args.request.prompt, "Explain local activity");
});

test("18. Multi-turn conversation preserves history and supports New Conversation", async () => {
  const app = bootAssistantTestApp();
  app.debug.setAiProviderForTest("local");

  app.debug.stageAiEvidenceForTest([
    { row_num: 1, fileName: "security.evtx", EventID: 4688, Process: "cmd.exe" },
  ]);

  // Turn 1
  await app.debug.sendLocalAiAnalysisForTest("First question");
  let hist = app.debug.getAiConversationHistoryForTest();
  assert.equal(hist.length, 2, "Turn 1 adds user and assistant message");
  assert.equal(hist[0].role, "user");
  assert.equal(hist[0].content, "First question");
  assert.equal(hist[1].role, "assistant");

  // Turn 2
  await app.debug.sendLocalAiAnalysisForTest("Second question");
  hist = app.debug.getAiConversationHistoryForTest();
  assert.equal(hist.length, 4, "Turn 2 adds second user and assistant message");
  const localCalls = app.tauriCalls.filter((call) => call.command === "local_ai_analyze_evidence");
  assert.match(localCalls[1].args.request.history[1].content, /\[E1\]/);
  assert.doesNotMatch(localCalls[1].args.request.history[1].content, /row #1/);

  // New Conversation clears history
  const newConvBtn = app.document.getElementById("ai-new-conversation-btn");
  assert.ok(newConvBtn, "New conversation button must exist");
  newConvBtn.click();

  hist = app.debug.getAiConversationHistoryForTest();
  assert.equal(hist.length, 0, "History must be empty after New Conversation");
});

test("19. Changing staged evidence or switching provider resets conversation history with notice", async () => {
  const app = bootAssistantTestApp();
  app.debug.setAiProviderForTest("local");

  app.debug.stageAiEvidenceForTest([
    { row_num: 1, fileName: "security.evtx", EventID: 4688 },
  ]);

  await app.debug.sendLocalAiAnalysisForTest("Inspect event");
  assert.equal(app.debug.getAiConversationHistoryForTest().length, 2);

  // Stage different evidence
  app.debug.stageAiEvidenceForTest([
    { row_num: 5, fileName: "sysmon.evtx", EventID: 1 },
  ]);

  assert.equal(
    app.debug.getAiConversationHistoryForTest().length,
    0,
    "Staging new evidence must reset conversation history"
  );
  const notice = app.document.getElementById("ai-conversation-notice");
  assert.match(notice.textContent, /Selected evidence changed/);

  // Add a turn again
  await app.debug.sendLocalAiAnalysisForTest("Inspect new event");
  assert.equal(app.debug.getAiConversationHistoryForTest().length, 2);

  // Switch provider to gemini
  app.debug.setAiProviderForTest("gemini");
  assert.equal(
    app.debug.getAiConversationHistoryForTest().length,
    0,
    "Switching provider must reset conversation history"
  );
  assert.match(notice.textContent, /Provider switched/);
});

test("20. Selections over the 75-row local context become an ordered chunk scope", () => {
  const app = bootAssistantTestApp();
  app.debug.setAiProviderForTest("local");

  // Generate 76 rows (exceeds local limit 75)
  const rows76 = [];
  for (let i = 1; i <= 76; i++) {
    rows76.push({ row_num: i, fileName: "test.csv", action: "logon" });
  }

  const result = app.debug.stageAiEvidenceForTest(rows76);
  assert.equal(result, true, "Selections over 75 rows must be retained for chunked analysis");
  const state = app.debug.getAiAssistantState();
  assert.equal(state.stagedEvidence, null);
  assert.equal(state.selectionScope.rows.length, 76);
});

test("21. UI labels honestly reflect Deterministic Offline vs gpt-oss Local and never say Local Qwen", () => {
  const app = bootAssistantTestApp();

  // Test when model is not installed / stopped
  app.debug.updateLocalRuntimeUiForTest({ status: "stopped", installed: false, modelName: "gpt-oss-20b" });
  const findPill = app.document.getElementById("ai-find-mode-pill");
  const findBadge = app.document.getElementById("ai-find-model-badge");

  assert.match(findPill.textContent, /Deterministic Offline/);
  assert.doesNotMatch(findPill.textContent, /Qwen/i);
  assert.match(findBadge.innerHTML, /Deterministic Offline/);
  assert.doesNotMatch(findBadge.innerHTML, /Qwen/i);

  // Installed but stopped starts the managed runtime on the next search.
  app.debug.updateLocalRuntimeUiForTest({ status: "stopped", installed: true, modelName: "gpt-oss-20b" });
  assert.match(findPill.textContent, /starts on search/);
  assert.match(findBadge.innerHTML, /gpt-oss-20b/);

  // Test when model is ready
  app.debug.updateLocalRuntimeUiForTest({ status: "ready", installed: true, modelName: "gpt-oss-20b" });
  assert.match(findPill.textContent, /gpt-oss Local \(ready\)/);
  assert.match(findBadge.innerHTML, /gpt-oss-20b/);
  assert.doesNotMatch(findPill.textContent, /Qwen/i);
});

test("22. Gemini row citations are displayed only when they match staged provenance", async () => {
  const app = bootAssistantTestApp({
    initialKey: "AIzaSyKey123",
    invokeHandler: async (command, args) => {
      if (command !== "gemini_generate") return undefined;
      return {
        model: args.request.model,
        text: "Observed [security.evtx | row #42] but also [security.evtx | row #999].",
      };
    },
  });
  app.debug.setAiProviderForTest("gemini");
  app.debug.stageAiEvidenceForTest([
    { row_num: 42, fileName: "security.evtx", EventID: 4688 },
  ]);

  await app.debug.sendGeminiAnalysisForTest("Check citations");
  const rendered = app.document.getElementById("ai-analysis-results-content").innerHTML;
  assert.match(rendered, /security\.evtx \| row #42/);
  assert.match(rendered, /Unverified citation removed/);
  assert.doesNotMatch(rendered, /row #999/);
});

test("23. The shipped index initializes Settings when removed legacy controls are absent", () => {
  const app = bootAssistantTestApp({ strictDom: true });
  const startupErrors = app.initializationErrors.filter((args) =>
    String(args[0] || "").includes("Initialization error")
  );

  assert.deepEqual(startupErrors, [], "The actual index.html must not abort app initialization");
  const settingsBtn = app.document.getElementById("settings-btn");
  assert.ok(settingsBtn, "The shipped Settings button must exist");
  assert.equal(
    (settingsBtn.listeners.get("click") || []).length,
    1,
    "Settings must receive its click handler even when legacy analyst controls are absent"
  );
  assert.doesNotThrow(
    () => app.debug.hideAnalystPanelForTest(),
    "Evidence loading must tolerate the removed legacy analyst drawer"
  );
});

test("24. The main window may display supported message-based confirmation dialogs", () => {
  const capability = JSON.parse(fs.readFileSync(CAPABILITY_PATH, "utf8"));
  assert.ok(
    capability.permissions.includes("dialog:default") || capability.permissions.includes("dialog:allow-message"),
    "Folder ingestion and the optional model download require dialog message permission"
  );
  assert.ok(
    !capability.permissions.includes("dialog:allow-confirm"),
    "The deprecated confirm alias must not mask use of the removed plugin command"
  );
});

test("25. Asynchronous Tauri message confirmation is awaited before starting a model download", async () => {
  let resolveConfirmation;
  const confirmation = new Promise((resolve) => { resolveConfirmation = resolve; });
  const app = bootAssistantTestApp({ confirmResult: confirmation });

  app.document.getElementById("local-ai-download-btn").click();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(
    app.tauriCalls.filter((call) => call.command === "local_ai_download_model").length,
    0,
    "A pending Promise must never be treated as examiner consent"
  );

  resolveConfirmation(true);
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(
    app.tauriCalls.filter((call) => call.command === "local_ai_download_model").length,
    1,
    "The download may start only after the awaited confirmation resolves true"
  );
  assert.equal(
    app.tauriCalls.filter((call) => call.command === "plugin:dialog|message").length,
    1,
    "Confirmation must use the supported Tauri message command"
  );
});

test("26. Folder selection reaches ingestion after the supported confirmation dialog", async () => {
  const folderPath = "C:\\cases\\evidence";
  const evidencePath = `${folderPath}\\events.csv`;
  const app = bootAssistantTestApp({
    confirmResult: true,
    invokeHandler: async (command) => {
      if (command === "plugin:dialog|open") return folderPath;
      if (command === "scan_evidence_directory") {
        return {
          folderPath,
          totalFilesFound: 1,
          totalBytes: 128,
          files: [{ path: evidencePath, name: "events.csv", extension: "csv", sizeBytes: 128 }],
        };
      }
      if (command === "list_sheets") return [];
      if (command === "batch_ensure_cached") return [];
      return undefined;
    },
  });

  await app.debug.pickAndOpenFolderForTest();
  await new Promise((resolve) => setTimeout(resolve, 0));

  assert.equal(
    app.tauriCalls.filter((call) => call.command === "plugin:dialog|message").length,
    1,
    "The discovered-folder prompt must use the supported message command"
  );
  assert.equal(app.debug.getLoadedFilesForTest().length, 1);
  assert.equal(app.debug.getLoadedFilesForTest()[0].path, evidencePath);
});

test("27. Master Timeline rows can be selected and staged in the AI Evidence Assistant", () => {
  const app = bootAssistantTestApp({ strictDom: true });
  app.debug.renderUnifiedCorrelatedGridForTest([
    {
      rowNum: 42,
      fileName: "security.evtx",
      path: "C:\\cases\\security.evtx",
      utcText: "2026-11-02T12:00:00Z",
      rawFields: { EventID: 4688, CommandLine: "powershell.exe -enc AAAA" },
    },
    {
      rowNum: 77,
      fileName: "sysmon.evtx",
      path: "C:\\cases\\sysmon.evtx",
      utcText: "2026-11-02T12:01:00Z",
      rawFields: { EventID: 1, Image: "powershell.exe" },
    },
    {
      rowNum: 88,
      fileName: "unrelated.csv",
      path: "C:\\cases\\unrelated.csv",
      utcText: "2026-11-02T12:02:00Z",
      rawFields: Object.fromEntries(Array.from({ length: 100 }, (_, i) => [`UnrelatedColumn${i}`, ""])),
    },
  ], "Forensic Master Timeline");

  assert.equal(FakeTabulator.latest.options.selectableRows, true);
  assert.equal(FakeTabulator.latest.options.selectableRowsRangeMode, "click");
  assert.equal(FakeTabulator.latest.options.selectableRowsPersistence, true);
  const stageBtn = app.document.getElementById("grid-stage-ai-btn");
  assert.equal(stageBtn.classList.contains("hidden"), false);
  assert.equal(stageBtn.disabled, false);
  assert.match(stageBtn.textContent, /Analyze 2 Selected Rows/);
  assert.equal(app.debug.stageCurrentGridSelectionForAiTest(), true);
  const staged = app.debug.getAiAssistantState().stagedEvidence;
  assert.equal(staged.rows.length, 2);
  assert.equal(staged.rows[0]._provenance.file, "security.evtx");
  assert.equal(staged.rows[0]._provenance.rowNumber, 42);
  assert.equal(staged.rows[0].CommandLine, "powershell.exe -enc AAAA");
  assert.ok(staged.columns.length < 60, "empty union-schema columns from unrelated files must not block staging");
  assert.equal(staged.columns.some((name) => name.startsWith("UnrelatedColumn")), false);
  assert.equal(app.document.getElementById("ai-staged-summary-card").classList.contains("hidden"), false);
});

test("28. The assistant opens as one conversation instead of a wall of prompt buttons", () => {
  assert.match(INDEX_SOURCE, /id="ai-mode-analyze" class="ai-mode-pane"/);
  assert.match(INDEX_SOURCE, /id="ai-mode-find" class="ai-mode-pane hidden"/);
  assert.match(INDEX_SOURCE, /id="ai-subtab-analyze-btn" class="ai-mode-btn active"/);
  assert.match(INDEX_SOURCE, /id="ai-prompt-template-select"/);
  assert.doesNotMatch(INDEX_SOURCE, /class="btn-prompt-template"/);
  assert.match(INDEX_SOURCE, /Ask a question about the evidence/);
});

test("29. Selected payload preview is provider-aware and does not claim local evidence was transmitted", () => {
  assert.match(INDEX_SOURCE, /id="ai-payload-modal-title">Selected Evidence Payload</);
  assert.match(INDEX_SOURCE, /Opening this preview never sends evidence anywhere/);
  assert.match(APP_SOURCE, /Selected Evidence \(Local Only\)/);
  assert.match(APP_SOURCE, /stays on this device/);
  assert.match(APP_SOURCE, /Gemini Cloud Preview/);
  assert.doesNotMatch(INDEX_SOURCE, /Transmitted to Gemini/);
});

test("30. Broad unstaged analysis is stopped before an unbounded evidence search", () => {
  const app = bootAssistantTestApp();
  const needsSelection = app.debug.assistantPromptNeedsExplicitSelectionForTest;

  assert.equal(needsSelection("What is in this file?"), true);
  assert.equal(needsSelection("Summarize the entire evidence dataset"), true);
  assert.equal(
    needsSelection("Reconstruct a strict chronological timeline of events from the staged evidence"),
    true
  );
  assert.equal(needsSelection("Find all anomalies and attack chains"), true);

  assert.equal(needsSelection("Find PowerShell execution"), false);
  assert.equal(needsSelection("Summarize failed logons for alice"), false);
  assert.equal(needsSelection("Analyze Event ID 4688"), false);
  assert.equal(needsSelection("Find activity for 192.168.0.15"), false);
});

test("31. Empty-assistant guidance requires selection for whole-file summaries", () => {
  assert.match(INDEX_SOURCE, /Whole-file summaries and timelines require an explicit row selection/);
  assert.match(APP_SOURCE, /I did not scan or silently sample the entire active file/);
  assert.doesNotMatch(
    INDEX_SOURCE,
    /Otherwise the assistant searches the active evidence first/
  );
});

test("32. Targeted Hunt does not duplicate the workspace file selector", () => {
  assert.doesNotMatch(INDEX_SOURCE, /Evidence Workspace Files/);
  assert.doesNotMatch(INDEX_SOURCE, /id="correlation-files-list"/);
  assert.doesNotMatch(APP_SOURCE, /correlationFilesList/);
});

test("33. Chunked local analysis supplies every selected timeline row exactly once", async () => {
  const suppliedRows = [];
  const app = bootAssistantTestApp({
    invokeHandler: async (command, args) => {
      if (command !== "local_ai_analyze_evidence") return undefined;
      const payload = JSON.parse(args.request.stagedEvidenceJson);
      const rows = payload.evidence;
      suppliedRows.push(...rows.map((row) => row._provenance.rowNumber));
      const first = rows[0]._provenance;
      return {
        text: `High-confidence attack evidence [${first.file} | row #${first.rowNumber}].`,
        historyText: "High-confidence attack evidence [E1].",
        provider: "local-llama-cpp",
        model: "gpt-oss-20b",
        modelVersion: "MXFP4@ggml-org",
        citations: [{ file: first.file, rowNumber: first.rowNumber, verified: true }],
      };
    },
  });
  app.debug.setAiProviderForTest("local");
  const rows = Array.from({ length: 80 }, (_, i) => ({
    row_num: i + 1,
    fileName: "timeline.evtx",
    utcText: `2026-11-05T12:${String(i % 60).padStart(2, "0")}:00Z`,
    EventID: 4688,
    CommandLine: i % 20 === 0 ? "powershell.exe -enc AAAA" : "svchost.exe",
  }));

  assert.equal(app.debug.stageAiEvidenceForTest(rows), true);
  assert.equal(app.debug.getAiAssistantState().selectionScope.rows.length, 80);
  await app.debug.askEvidenceAssistantForTest("Identify the most important and obvious attacks");

  assert.deepEqual(suppliedRows, Array.from({ length: 80 }, (_, i) => i + 1));
  assert.equal(
    app.tauriCalls.filter((call) => call.command === "local_ai_analyze_evidence").length,
    2,
    "80 local rows must be processed as 75 + 5 without omission"
  );
  assert.equal(app.debug.getAiAssistantState().attackTimelineRows.length, 2);
  assert.match(app.document.getElementById("ai-results-meta").textContent, /80\/80 selected rows supplied/);
});

test("34. A disconnected local runtime is restarted and retried once", async () => {
  let attempts = 0;
  const app = bootAssistantTestApp({
    invokeHandler: async (command) => {
      if (command === "local_ai_analyze_evidence") {
        attempts += 1;
        if (attempts === 1) {
          throw new Error("Local AI analysis request failed: error sending request for url (http://127.0.0.1:39525/v1/chat/completions)");
        }
        return {
          text: "Attack observed [security.evtx | row #42].",
          historyText: "Attack observed [E1].",
          provider: "local-llama-cpp",
          model: "gpt-oss-20b",
          modelVersion: "MXFP4@ggml-org",
          citations: [{ file: "security.evtx", rowNumber: 42, verified: true }],
        };
      }
      if (command === "local_ai_runtime_stop" || command === "local_ai_runtime_start") return { status: "ready" };
      return undefined;
    },
  });
  app.debug.setAiProviderForTest("local");
  app.debug.stageAiEvidenceForTest([{ row_num: 42, fileName: "security.evtx", EventID: 4688 }]);
  await app.debug.sendLocalAiAnalysisForTest("Find the attack");

  assert.equal(attempts, 2);
  assert.equal(app.tauriCalls.filter((call) => call.command === "local_ai_runtime_stop").length, 1);
  assert.equal(app.tauriCalls.filter((call) => call.command === "local_ai_runtime_start").length, 1);
});

test("35. AI-cited attack rows export through the Master Timeline workbook path", async () => {
  const app = bootAssistantTestApp({
    invokeHandler: async (command, args) => {
      if (command === "local_ai_analyze_evidence") {
        return {
          text: "Obvious execution attack [security.evtx | row #42].",
          historyText: "Obvious execution attack [E1].",
          provider: "local-llama-cpp",
          model: "gpt-oss-20b",
          modelVersion: "MXFP4@ggml-org",
          citations: [{ file: "security.evtx", rowNumber: 42, verified: true }],
        };
      }
      if (command === "plugin:dialog|save") return "C:\\exports\\ai-attack-master-timeline.xlsx";
      if (command === "export_unified_multisheet_xlsx") {
        return { totalEvents: args.events.length, sheetsWritten: ["Unified Timeline"] };
      }
      return undefined;
    },
  });
  app.debug.setAiProviderForTest("local");
  app.debug.stageAiEvidenceForTest([{
    row_num: 42,
    fileName: "security.evtx",
    path: "C:\\cases\\security.evtx",
    utcText: "2026-11-05T12:00:00Z",
    EventID: 4688,
    CommandLine: "powershell.exe -enc AAAA",
  }]);
  await app.debug.sendLocalAiAnalysisForTest("Find the attack");

  const exportButton = app.document.getElementById("ai-export-attack-timeline-btn");
  assert.equal(exportButton.classList.contains("hidden"), false);
  exportButton.click();
  await new Promise((resolve) => setTimeout(resolve, 0));

  const exportCall = app.tauriCalls.find((call) => call.command === "export_unified_multisheet_xlsx");
  assert.ok(exportCall);
  assert.equal(exportCall.args.events.length, 1);
  assert.equal(exportCall.args.events[0].rowNum, 42);
  assert.equal(exportCall.args.events[0].fileName, "security.evtx");
});

test("36. A stopped local runtime is started before the analysis request", async () => {
  const commandOrder = [];
  const app = bootAssistantTestApp({
    invokeHandler: async (command) => {
      commandOrder.push(command);
      if (command === "local_ai_runtime_status") {
        return { status: "stopped", installed: true, modelName: "gpt-oss-20b", error: null };
      }
      if (command === "local_ai_runtime_start") {
        return { status: "ready", installed: true, modelName: "gpt-oss-20b", error: null };
      }
      if (command === "local_ai_analyze_evidence") {
        return {
          text: "No obvious attack activity is supported by this row.",
          historyText: "No obvious attack activity is supported by this row.",
          provider: "local-llama-cpp",
          model: "gpt-oss-20b",
          modelVersion: "MXFP4@ggml-org",
          citations: [],
        };
      }
      return undefined;
    },
  });
  app.debug.setAiProviderForTest("local");
  app.debug.stageAiEvidenceForTest([{ row_num: 5, fileName: "timeline.evtx", EventID: 1 }]);
  await app.debug.sendLocalAiAnalysisForTest("Find obvious attacks");

  const statusIndex = commandOrder.indexOf("local_ai_runtime_status");
  const startIndex = commandOrder.indexOf("local_ai_runtime_start");
  const analyzeIndex = commandOrder.indexOf("local_ai_analyze_evidence");
  assert.ok(statusIndex >= 0 && startIndex > statusIndex && analyzeIndex > startIndex);
  assert.equal(commandOrder.filter((command) => command === "local_ai_analyze_evidence").length, 1);
});
