/**
 * CPoE Browser Extension — Options Script
 */

const DEFAULT_SITES = {
	"google-docs": { label: "Google Docs", enabled: true },
	overleaf: { label: "Overleaf", enabled: true },
	medium: { label: "Medium", enabled: true },
	notion: { label: "Notion", enabled: true },
	craft: { label: "Craft", enabled: true },
	coda: { label: "Coda", enabled: true },
	clickup: { label: "ClickUp Docs", enabled: true },
	nuclino: { label: "Nuclino", enabled: true },
	stackedit: { label: "StackEdit", enabled: true },
	hackmd: { label: "HackMD", enabled: true },
	hemingway: { label: "Hemingway Editor", enabled: true },
	quillbot: { label: "QuillBot", enabled: false },
	etherpad: { label: "Etherpad", enabled: true },
	"riseup-pad": { label: "Riseup Pad", enabled: true },
	"write-as": { label: "Write.as", enabled: true },
	wordpress: { label: "WordPress", enabled: true },
	ghost: { label: "Ghost", enabled: true },
	substack: { label: "Substack", enabled: true },
};

const DEFAULTS = {
	autoWitness: false,
	autoDetectEditors: false,
	checkpointInterval: 30,
	contentTier: "enhanced",
	captureJitter: true,
	enabledSites: Object.fromEntries(
		Object.entries(DEFAULT_SITES).map(([k, v]) => [k, v.enabled]),
	),
	customDomains: [],
};

const elements = {
	autoWitness: document.getElementById("auto-witness"),
	autoDetectEditors: document.getElementById("auto-detect-editors"),
	checkpointInterval: document.getElementById("checkpoint-interval"),
	contentTier: document.getElementById("content-tier"),
	captureJitter: document.getElementById("capture-jitter"),
	btnSave: document.getElementById("btn-save"),
	saveStatus: document.getElementById("save-status"),
	siteList: document.getElementById("site-list"),
	customDomainsList: document.getElementById("custom-domains-list"),
	customDomainInput: document.getElementById("custom-domain-input"),
	btnAddDomain: document.getElementById("btn-add-domain"),
};

let currentCustomDomains = [];

function renderBuiltinSites(enabledSites) {
	elements.siteList.replaceChildren();
	for (const [key, info] of Object.entries(DEFAULT_SITES)) {
		const label = document.createElement("label");
		label.className = "site-toggle";
		const input = document.createElement("input");
		input.type = "checkbox";
		input.dataset.site = key;
		input.checked = enabledSites?.[key] ?? info.enabled;
		label.appendChild(input);
		label.appendChild(document.createTextNode(" " + info.label));
		elements.siteList.appendChild(label);
	}
}

function renderCustomDomains() {
	elements.customDomainsList.replaceChildren();
	for (const domain of currentCustomDomains) {
		const row = document.createElement("div");
		row.className = "custom-domain-row";
		row.setAttribute("role", "listitem");

		const span = document.createElement("span");
		span.className = "custom-domain-name";
		span.textContent = domain;

		const btn = document.createElement("button");
		btn.className = "btn-remove";
		btn.type = "button";
		btn.textContent = "\u00d7";
		btn.setAttribute("aria-label", "Remove " + domain);
		btn.title = "Remove " + domain;
		btn.addEventListener("click", () => {
			currentCustomDomains = currentCustomDomains.filter(
				(d) => d !== domain,
			);
			renderCustomDomains();
		});

		row.appendChild(span);
		row.appendChild(btn);
		elements.customDomainsList.appendChild(row);
	}
}

async function addCustomDomain() {
	let raw = elements.customDomainInput.value.trim();
	if (!raw) return;

	// Normalize: strip protocol, trailing slashes
	raw = raw.replace(/^https?:\/\//, "").replace(/\/+$/, "");

	// Validate: optional leading *. then at least 2 non-wildcard domain segments
	// (e.g., *.example.com is ok; *.com, *.*, or bare TLDs are rejected)
	if (
		!/^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$/i.test(
			raw,
		)
	) {
		elements.saveStatus.textContent = "Invalid domain format";
		setTimeout(() => {
			elements.saveStatus.textContent = "";
		}, 2000);
		return;
	}
	const nonWildcard = raw.replace(/^\*\./, "");
	if (nonWildcard.split(".").length < 2) {
		elements.saveStatus.textContent =
			"Domain too broad (need at least name.tld)";
		setTimeout(() => {
			elements.saveStatus.textContent = "";
		}, 2000);
		return;
	}

	if (currentCustomDomains.includes(raw)) {
		elements.saveStatus.textContent = "Domain already added";
		setTimeout(() => {
			elements.saveStatus.textContent = "";
		}, 2000);
		elements.customDomainInput.value = "";
		return;
	}

	// Build host permission pattern; wildcard only at subdomain level
	const pattern = raw.startsWith("*.")
		? `https://*.${raw.slice(2)}/*`
		: `https://${raw}/*`;
	let granted = false;
	try {
		granted = await chrome.permissions.request({ origins: [pattern] });
	} catch {
		granted = false;
	}

	if (!granted) {
		elements.saveStatus.textContent = "Permission denied for " + raw;
		setTimeout(() => {
			elements.saveStatus.textContent = "";
		}, 3000);
		return;
	}

	currentCustomDomains.push(raw);
	renderCustomDomains();
	elements.customDomainInput.value = "";
}

async function loadSettings() {
	const result = await chrome.storage.local.get(Object.keys(DEFAULTS));
	const settings = { ...DEFAULTS, ...result };

	elements.autoWitness.checked = settings.autoWitness;
	elements.autoDetectEditors.checked = settings.autoDetectEditors;
	elements.checkpointInterval.value = settings.checkpointInterval;
	elements.contentTier.value = settings.contentTier;
	elements.captureJitter.checked = settings.captureJitter;

	renderBuiltinSites(settings.enabledSites);

	currentCustomDomains = settings.customDomains || [];
	renderCustomDomains();
}

async function saveSettings() {
	const enabledSites = {};
	document
		.querySelectorAll(".site-toggle input[data-site]")
		.forEach((input) => {
			enabledSites[input.dataset.site] = input.checked;
		});

	const settings = {
		autoWitness: elements.autoWitness.checked,
		autoDetectEditors: elements.autoDetectEditors.checked,
		checkpointInterval: Math.max(
			10,
			Math.min(
				300,
				parseInt(elements.checkpointInterval.value, 10) || 30,
			),
		),
		contentTier: ["core", "enhanced", "maximum"].includes(
			elements.contentTier.value,
		)
			? elements.contentTier.value
			: "enhanced",
		captureJitter: elements.captureJitter.checked,
		enabledSites,
		customDomains: currentCustomDomains,
	};

	await chrome.storage.local.set(settings);

	elements.saveStatus.textContent = "Saved";
	setTimeout(() => {
		elements.saveStatus.textContent = "";
	}, 2000);
}

elements.btnSave.addEventListener("click", saveSettings);
elements.btnAddDomain.addEventListener("click", addCustomDomain);
elements.customDomainInput.addEventListener("keydown", (e) => {
	if (e.key === "Enter") {
		e.preventDefault();
		addCustomDomain();
	}
});

loadSettings();
