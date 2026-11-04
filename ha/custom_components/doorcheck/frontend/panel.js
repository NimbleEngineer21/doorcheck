// Native controls and text nodes only. No scanned value becomes HTML, a URL or CSS.
const ASSETS = new URL('.', import.meta.url);
const PAGE = 50;
function node(tag, text, attrs = {}) {
  const value = document.createElement(tag);
  if (text !== undefined && text !== null) {
    value.textContent = String(text);
    value.dir = "auto";
  }
  for (const [key, content] of Object.entries(attrs)) value.setAttribute(key, content);
  return value;
}

class DoorcheckPanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({mode: 'open'});
    this.epoch = 0;
    this.items = [];
    this.selected = '';
    this.busy = false;
    this.report = null;
    this.counts = {findings: PAGE, capabilities: PAGE};
    this.live = node('p', '', {role: 'status', 'aria-live': 'polite', 'aria-atomic': 'true'});
    this.content = node('main');
    this.shadowRoot.append(this.live, this.content);
  }
  set panel(value) { this._panel = value; this.start(); }
  get panel() { return this._panel; }
  set hass(value) {
    const session = [value.user?.id, value.user?.is_admin, value.connection, value.connected];
    if (this.session && session.some((value, index) => value !== this.session[index])) this.clear();
    this.session = session;
    this._hass = value;
    this.setAttribute('data-theme', value.themes?.darkMode ? 'dark' : 'light');
    this.start();
  }
  get hass() { return this._hass; }
  connectedCallback() { this.start(); }
  disconnectedCallback() { this.clear(); }
  clear() {
    this.epoch++;
    this.started = false;
    this.busy = false;
    this.items = [];
    this.inventory = null;
    this.selected = '';
    this.report = null;
    this.error = '';
    this.live.textContent = '';
    this.content.replaceChildren();
  }
  get messages() { return this._panel.config.messages; }
  start() {
    if (!this.isConnected || !this._panel?.config || !this._hass) return;
    if (!this.styles) {
      this.styles = node('style', this._panel.config.tokens);
      const css = node('link', null, {rel: 'stylesheet', href: new URL('panel.css', ASSETS).href});
      this.shadowRoot.prepend(this.styles, css);
    }
    if (!this._hass.user?.is_admin) {
      this.clear();
      this.content.replaceChildren(node('p', this.messages.admin, {role: 'alert'}));
      return;
    }
    if (this._hass.connected === false) {
      this.error = this.messages.error;
      this.render();
      return;
    }
    if (!this.started) {
      this.started = true;
      this.refresh();
    }
  }
  async request(type, data = {}) {
    return this._hass.callWS({type: `doorcheck/panel_${type}`, ...data});
  }
  async perform(task, apply, message) {
    const generation = ++this.epoch;
    this.busy = true;
    this.error = '';
    this.live.textContent = message;
    this.render();
    try {
      const result = await task();
      if (generation !== this.epoch || !this.isConnected) return;
      apply(result);
    } catch (error) {
      if (generation !== this.epoch || !this.isConnected) return;
      const known = ['scan_busy', 'scan_invalid_directory', 'inventory_not_configured'];
      this.error = known.includes(error?.translation_key)
        ? this.messages[error.translation_key] : this.messages.error;
      if (error?.code === 'unauthorized') {
        this.items = [];
        this.inventory = null;
        this.selected = '';
        this.error = this.messages.admin;
      }
    } finally {
      if (generation === this.epoch && this.isConnected) {
        this.busy = false;
        this.live.textContent = '';
        this.render();
        if (this.report) this.shadowRoot.querySelector('#results').focus();
        if (this.error) this.shadowRoot.querySelector('[role="alert"]').focus();
      }
    }
  }
  refresh() {
    if (this.busy) return;
    this.report = null;
    this.selected = '';
    this.items = [];
    this.inventory = null;
    return this.perform(() => this.request('inventory'), result => {
      this.inventory = result;
      this.items = result.items;
      this.selected = this.items[0]?.directory || '';
    }, this.messages.loading);
  }
  scan() {
    if (this.busy || !this.selected) return;
    this.report = null;
    this.counts = {findings: PAGE, capabilities: PAGE};
    const directory = this.selected;
    return this.perform(() => this.request('scan', {directory}), result => {
      this.report = result;
    }, this.messages.scanning);
  }
  button(label, id, action, disabled = false) {
    const button = node('button', label, {type: 'button', id});
    button.disabled = disabled;
    button.addEventListener('click', action);
    return button;
  }
  render() {
    const focus = this.shadowRoot.activeElement?.id;
    const m = this.messages;
    const header = node('header');
    const menu = this.button(m.menu, 'menu', () => this.dispatchEvent(
      new CustomEvent('hass-toggle-menu', {bubbles: true, composed: true})));
    header.append(menu, node('h1', m.title));
    const intro = node('p', m.intro, {class: 'intro'});
    const controls = node('div', null, {class: 'controls'});
    const label = node('label', m.integration, {for: 'integration'});
    const select = node('select', null, {id: 'integration'});
    for (const item of this.items) {
      const option = node('option', item.name, {value: item.directory, dir: 'auto'});
      option.selected = item.directory === this.selected;
      select.append(option);
    }
    select.disabled = this.busy || !this.items.length;
    select.addEventListener('change', () => {
      this.selected = select.value;
      this.report = null;
      this.error = '';
      this.render();
    });
    const field = node('div', null, {class: 'field'});
    field.append(label, select);
    controls.append(field, this.button(m.scan, 'scan', () => this.scan(), this.busy || !this.selected || this._hass.connected === false),
      this.button(m.refresh, 'refresh', () => this.refresh(), this.busy || this._hass.connected === false));
    const children = [header, intro, controls];
    if (this.error) children.push(node('p', this.error, {role: 'alert', tabindex: '-1'}));
    if (this.inventory) {
      const inventory = node('section', null, {class: 'inventory'});
      inventory.append(node('p', m.unknown_origin, {class: 'muted'}));
      if (!this.inventory.complete) inventory.append(node('p', this.inventory.status), node('p', m.incomplete));
      for (const problem of this.inventory.problems) inventory.append(node('p', problem));
      const item = this.items.find(item => item.directory === this.selected);
      if (item) {
        const identity = node('p', null, {class: 'identity'});
        identity.append(node('bdi', item.directory, {dir: 'auto'}));
        if (item.version) identity.append(document.createTextNode(' / '), node('bdi', item.version, {dir: 'auto'}));
        inventory.append(identity);
        for (const problem of item.problems) inventory.append(node('p', problem));
      }
      children.push(inventory);
    }
    if (this.report) children.push(this.results());
    else if (!this.busy) children.push(node('p', this.items.length ? m.ready : m.empty));
    this.content.replaceChildren(...children);
    this.content.setAttribute('aria-busy', String(this.busy));
    if (focus) this.shadowRoot.getElementById(focus)?.focus();
  }
  results() {
    const report = this.report, m = this.messages;
    const results = node('section', null, {id: 'results', tabindex: '-1', 'aria-label': report.target});
    results.append(node('h2', report.target, {dir: 'auto'}));
    if (!report.complete) results.append(node('p', m.incomplete, {class: 'gap'}));
    const coverage = node('section', null, {'aria-label': m.coverage});
    coverage.append(node('h3', m.coverage));
    for (const check of report.checks) {
      coverage.append(node('p', `${check.name}: ${check.status}`));
      for (const problem of check.problems) {
        coverage.append(node('p', problem.message, {class: 'gap'}));
        if (problem.location) coverage.append(node('code', problem.location, {dir: 'ltr'}));
      }
    }
    results.append(coverage, this.list('findings'), this.list('capabilities'));
    return results;
  }
  list(kind) {
    const m = this.messages, values = this.report[kind];
    const section = node('section', null, {'aria-label': m[kind]});
    section.append(node('h3', `${m[kind]} (${values.length})`, {id: `list-${kind}`, tabindex: '-1'}));
    if (!values.length) section.append(node('p', m[`no_${kind}`]));
    for (const item of values.slice(0, this.counts[kind])) {
      const article = node('article');
      if (kind === 'findings') article.append(node('strong', item.label, {class: `severity ${item.severity}`}));
      article.append(node('p', item.message), node('code', item.location, {dir: 'ltr'}));
      if (item.action) article.append(node('p', item.action));
      if (kind === 'findings') {
        const details = node('details');
        details.append(node('summary', m.technical), node('code', item.rule, {dir: 'ltr'}),
          node('p', item.confidence));
        if (item.detail) details.append(node('p', item.detail));
        if (item.evidence) details.append(node('h4', m.evidence), node('pre', item.evidence, {dir: 'ltr'}));
        article.append(details);
      }
      section.append(article);
    }
    if (values.length > this.counts[kind]) section.append(this.button(m.more, `more-${kind}`, () => {
      this.counts[kind] += PAGE;
      this.render();
      this.shadowRoot.getElementById(`list-${kind}`).focus();
    }));
    return section;
  }
}
if (!customElements.get('doorcheck-panel')) customElements.define('doorcheck-panel', DoorcheckPanel);
