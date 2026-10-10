const PASSWORD_KEY = "contract-pages-password";
const FAILURE_KEY = "contract-pages-failures";
const BLOCKED_UNTIL_KEY = "contract-pages-blocked-until";
const FAILURE_LIMIT = 5;
const BLOCK_DURATION_MS = 15 * 60 * 1000;

const accessView = document.querySelector("#access-view");
const dashboardView = document.querySelector("#dashboard-view");
const unlockForm = document.querySelector("#unlock-form");
const passwordInput = document.querySelector("#access-password");
const unlockButton = document.querySelector("#unlock-button");
const accessError = document.querySelector("#access-error");
const statusFilter = document.querySelector("#status-filter");
const contractSearch = document.querySelector("#contract-search");

let encryptedPayload;
let contractSnapshot;

unlockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await unlock(passwordInput.value);
});

document.querySelector("#lock-button").addEventListener("click", () => {
  sessionStorage.removeItem(PASSWORD_KEY);
  contractSnapshot = undefined;
  window.location.reload();
});

statusFilter.addEventListener("change", renderInventory);
contractSearch.addEventListener("input", renderInventory);

start();

async function start() {
  try {
    encryptedPayload = await fetch("./contracts.enc.json", {
      cache: "no-store",
    }).then((response) => {
      if (!response.ok) throw new Error("合同数据暂时不可用");
      return response.json();
    });
  } catch {
    setAccessError("合同数据暂时不可用，请稍后刷新重试。");
    unlockButton.disabled = true;
    return;
  }

  const storedPassword = sessionStorage.getItem(PASSWORD_KEY);
  if (storedPassword) await unlock(storedPassword, true);
}

async function unlock(password, silent = false) {
  const blockedUntil = Number(sessionStorage.getItem(BLOCKED_UNTIL_KEY) || 0);
  if (blockedUntil > Date.now()) {
    const minutes = Math.ceil((blockedUntil - Date.now()) / 60000);
    setAccessError(`尝试次数过多，请 ${minutes} 分钟后再试。`);
    return;
  }
  if (Array.from(password).length < 12) {
    if (!silent) setAccessError("访问密码至少需要 12 个字符。");
    passwordInput.value = "";
    return;
  }

  unlockButton.disabled = true;
  unlockButton.textContent = "正在解密…";
  setAccessError("");
  try {
    contractSnapshot = await decryptSnapshot(encryptedPayload, password);
    sessionStorage.setItem(PASSWORD_KEY, password);
    sessionStorage.removeItem(FAILURE_KEY);
    sessionStorage.removeItem(BLOCKED_UNTIL_KEY);
    passwordInput.value = "";
    showDashboard();
  } catch {
    sessionStorage.removeItem(PASSWORD_KEY);
    const failures = Number(sessionStorage.getItem(FAILURE_KEY) || 0) + 1;
    sessionStorage.setItem(FAILURE_KEY, String(failures));
    if (failures >= FAILURE_LIMIT) {
      sessionStorage.setItem(
        BLOCKED_UNTIL_KEY,
        String(Date.now() + BLOCK_DURATION_MS),
      );
      setAccessError("尝试次数过多，请 15 分钟后再试。");
    } else if (!silent) {
      setAccessError(`访问密码不正确，还可尝试 ${FAILURE_LIMIT - failures} 次。`);
    }
    passwordInput.value = "";
  } finally {
    unlockButton.disabled = false;
    unlockButton.textContent = "解锁合同网页";
  }
}

async function decryptSnapshot(encrypted, password) {
  if (
    encrypted.version !== 1 ||
    encrypted.algorithm !== "AES-GCM" ||
    encrypted.keyDerivation !== "PBKDF2-SHA-256" ||
    encrypted.iterations !== 310000
  ) {
    throw new Error("不支持的数据格式");
  }

  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: encrypted.iterations,
      salt: fromBase64Url(encrypted.salt),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64Url(encrypted.iv) },
    key,
    fromBase64Url(encrypted.ciphertext),
  );
  const snapshot = JSON.parse(new TextDecoder().decode(plaintext));
  if (snapshot.version !== 1 || !Array.isArray(snapshot.allContracts)) {
    throw new Error("合同数据格式无效");
  }
  return snapshot;
}

function fromBase64Url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(
    normalized.length + ((4 - (normalized.length % 4)) % 4),
    "=",
  );
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function showDashboard() {
  accessView.hidden = true;
  dashboardView.hidden = false;
  document.title = "合同到期提醒";

  setText("#document-title", contractSnapshot.documentTitle || "合同信息表");
  setText("#checked-on", contractSnapshot.checkedOn);
  setText(
    "#generated-at",
    `更新于 ${new Date(contractSnapshot.generatedAt).toLocaleString("zh-CN")}`,
  );
  setText("#summary-total", contractSnapshot.summary.total);
  setText("#summary-today", contractSnapshot.summary.dueToday);
  setText("#summary-seven", contractSnapshot.summary.within7Days);
  setText("#summary-all", contractSnapshot.allContracts.length);
  renderRows(
    document.querySelector("#due-contracts-body"),
    contractSnapshot.dueContracts,
  );
  document.querySelector("#due-empty").hidden =
    contractSnapshot.dueContracts.length > 0;
  renderInventory();
}

function renderInventory() {
  if (!contractSnapshot) return;
  const status = statusFilter.value;
  const query = contractSearch.value.trim().toLocaleLowerCase("zh-CN");
  const filtered = contractSnapshot.allContracts.filter((contract) => {
    if (status && contract.status !== status) return false;
    if (!query) return true;
    return [contract.contractNumber, contract.partner, contract.name]
      .join(" ")
      .toLocaleLowerCase("zh-CN")
      .includes(query);
  });

  renderRows(document.querySelector("#all-contracts-body"), filtered);
  setText(
    "#inventory-count",
    `显示 ${filtered.length} 份，共 ${contractSnapshot.allContracts.length} 份`,
  );
  document.querySelector("#all-empty").hidden = filtered.length > 0;
}

function renderRows(tbody, contracts) {
  tbody.replaceChildren(
    ...contracts.map((contract) => {
      const row = document.createElement("tr");
      appendCell(row, contract.contractNumber);
      appendCell(row, contract.partner);
      appendCell(row, contract.name);
      appendCell(row, contract.expiryDate || "日期异常");
      appendCell(
        row,
        contract.daysRemaining === null
          ? "—"
          : contract.daysRemaining < 0
            ? `已过期 ${Math.abs(contract.daysRemaining)} 天`
            : contract.daysRemaining === 0
              ? "今天到期"
              : `剩余 ${contract.daysRemaining} 天`,
      );
      const statusCell = appendCell(row, contract.status || "未填写");
      statusCell.dataset.status = contract.status || "";
      return row;
    }),
  );
}

function appendCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = String(value ?? "");
  row.append(cell);
  return cell;
}

function setText(selector, value) {
  document.querySelector(selector).textContent = String(value ?? "");
}

function setAccessError(message) {
  accessError.textContent = message || "\u00a0";
}
