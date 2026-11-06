// Native controls and text nodes only. No scanned value becomes HTML, a URL or CSS.
const ASSETS = new URL('.', import.meta.url);
const PAGE = 50;
const KNOWN_ERRORS = [
  'scan_busy', 'scan_invalid_directory', 'inventory_not_configured', 'results_incomplete',
  'results_not_found', 'results_not_saving', 'results_stale', 'results_write_failed',
];
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
    this.saved = null;
    this.notice = '';
    this.full = null;
    this.queued = false;
    this.counts = {};
    this.live = node('p', '', {role: 'status', 'aria-live': 'polite', 'aria-atomic': 'true'});
    this.content = node('main');
    this.dialog = node('dialog', null, {'aria-labelledby': 'clear-title', 'aria-describedby': 'clear-detail'});
    this.dialog.addEventListener('close', () => this.closed());
    this.shadowRoot.append(this.live, this.content, this.dialog);
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
    this.saved = null;
    this.error = '';
    this.notice = '';
    this.queued = false;
    this.live.textContent = '';
    this.content.replaceChildren();
    if (this.dialog.open) this.dialog.close('');
  }
  get messages() { return this._panel.config.messages; }
  start() {
    if (!this.isConnected || !this._panel?.config || !this._hass) return;
    if (!this.styles) {
      this.styles = node('style', this._panel.config.tokens);
      const css = node('link', null, {rel: 'stylesheet', href: new URL('panel.css', ASSETS).href});
      this.shadowRoot.prepend(this.styles, css);
      this.confirmation();
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
  confirmation() {
    const m = this.messages;
    const form = node('form', null, {method: 'dialog'});
    const actions = node('div', null, {class: 'actions'});
    const cancel = node('button', m.cancel, {value: 'cancel', id: 'clear-cancel', autofocus: ''});
    actions.append(cancel, node('button', m.clear_confirm, {value: 'clear', id: 'clear-confirm'}));
    form.append(node('h2', m.clear_title, {id: 'clear-title'}),
      node('p', m.clear_detail, {id: 'clear-detail'}), actions);
    this.dialog.append(form);
  }
  async request(type, data = {}) {
    return this._hass.callWS({type: `doorcheck/panel_${type}`, ...data});
  }
  async perform(task, apply, message) {
    const generation = ++this.epoch;
    this.busy = true;
    this.error = '';
    this.notice = '';
    this.live.textContent = message;
    this.render();
    try {
      const result = await task();
      if (generation !== this.epoch || !this.isConnected) return;
      apply(result);
    } catch (error) {
      if (generation !== this.epoch || !this.isConnected) return;
      this.error = this.describe(error);
      if (error?.code === 'unauthorized') {
        this.items = [];
        this.inventory = null;
        this.selected = '';
        this.saved = null;
        this.error = this.messages.admin;
      }
    } finally {
      if (generation === this.epoch && this.isConnected) {
        this.busy = false;
        this.live.textContent = this.notice;
        this.render();
        if (this.saved) this.shadowRoot.querySelector('#results').focus();
        if (this.error) this.shadowRoot.querySelector('[role="alert"]').focus();
        if (this.queued) this.clearSaved();
      }
    }
  }
  describe(error) {
    return KNOWN_ERRORS.includes(error?.translation_key)
      ? this.messages[error.translation_key] : this.messages.error;
  }
  show(saved) {
    this.saved = saved;
    this.counts = {};
    this.full = null;
  }
  refresh() {
    if (this.busy) return;
    this.saved = null;
    this.selected = '';
    this.items = [];
    this.inventory = null;
    return this.perform(async () => {
      const inventory = await this.request('inventory');
      const directory = inventory.items[0]?.directory;
      let saved = null, failure = null;
      try {
        if (directory) saved = await this.request('results', {directory});
      } catch (error) {
        // One unreadable item (such as an invalid folder name) must not hide the inventory.
        if (error?.code === 'unauthorized') throw error;
        failure = error;
      }
      return {inventory, saved, failure};
    }, result => {
      this.inventory = result.inventory;
      this.items = result.inventory.items;
      this.selected = this.items[0]?.directory || '';
      this.show(result.saved);
      if (result.failure) this.error = this.describe(result.failure);
    }, this.messages.loading);
  }
  open() {
    if (this.busy || !this.selected) return;
    const directory = this.selected;
    return this.perform(() => this.request('results', {directory}), result => this.show(result),
      this.messages.opening);
  }
  scan() {
    if (this.busy || !this.selected) return;
    // The saved result stays on screen until a new result replaces it.
    const directory = this.selected;
    return this.perform(() => this.request('scan', {directory}), result => this.show(result),
      this.messages.scanning);
  }
  review() {
    if (this.busy || !this.saved?.reviewable) return;
    const directory = this.selected, scan_id = this.saved.latest.scan_id;
    return this.perform(async () => {
      try {
        return {saved: await this.request('review', {directory, scan_id})};
      } catch (error) {
        if (error?.translation_key !== 'results_stale') throw error;
        // Show the scan that is now the latest, so the next review names it.
        return {saved: await this.request('results', {directory}), error: 'results_stale'};
      }
    }, result => {
      this.show(result.saved);
      if (result.error) this.error = this.messages[result.error];
    }, this.messages.reviewing);
  }
  confirmClear() {
    if (this.busy) return;
    this.dialog.returnValue = '';
    this.dialog.showModal();
  }
  closed() {
    if (this.dialog.returnValue !== 'clear' || !this.started) {
      this.shadowRoot.getElementById('clear')?.focus();
      return;
    }
    // A confirmed clear is never dropped: it runs when the current work ends.
    if (this.busy) this.queued = true;
    else return this.clearSaved();
  }
  clearSaved() {
    this.queued = false;
    const directory = this.selected;
    return this.perform(async () => {
      await this.request('clear');
      // The store is gone even if reading it back fails.
      this.show(null);
      this.notice = this.messages.cleared;
      return directory ? this.request('results', {directory}) : null;
    }, result => this.show(result), this.messages.clearing);
  }
  button(label, id, action, disabled = false) {
    const button = node('button', label, {type: 'button', id});
    button.disabled = disabled;
    button.addEventListener('click', action);
    return button;
  }
  render() {
    const focus = this.shadowRoot.activeElement?.id;
    const m = this.messages, offline = this._hass.connected === false;
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
      this.saved = null;
      this.open();
    });
    const field = node('div', null, {class: 'field'});
    field.append(label, select);
    controls.append(field,
      this.button(m.scan, 'scan', () => this.scan(), this.busy || !this.selected || offline),
      this.button(m.refresh, 'refresh', () => this.refresh(), this.busy || offline),
      this.button(m.clear, 'clear', () => this.confirmClear(), this.busy || !this.inventory || offline));
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
    if (this.saved) children.push(this.results(offline));
    else if (!this.busy) children.push(node('p', this.items.length ? m.ready : m.empty));
    this.content.replaceChildren(...children);
    this.content.setAttribute('aria-busy', String(this.busy));
    if (focus) this.shadowRoot.getElementById(focus)?.focus();
  }
  time(label, value) {
    const text = node('p', `${label}: `);
    const time = node('time', value, {datetime: value});
    try {
      const zone = this._hass.config?.time_zone || 'UTC';
      time.textContent = new Intl.DateTimeFormat(this._hass.locale?.language || undefined,
        {dateStyle: 'medium', timeStyle: 'long', timeZone: zone}).format(new Date(value));
    } catch {
      // An unknown language or time zone keeps the saved ISO time.
    }
    text.append(time);
    return text;
  }
  results(offline) {
    const saved = this.saved, m = this.messages, latest = saved.latest;
    const results = node('section', null, {id: 'results', tabindex: '-1'});
    for (const problem of saved.problems) results.append(node('p', problem, {class: 'gap'}));
    if (!latest) {
      results.setAttribute('aria-label', m.no_saved);
      results.append(node('p', m.no_saved));
      return results;
    }
    const report = latest.report;
    results.setAttribute('aria-label', report.target);
    results.append(node('h2', report.target, {dir: 'auto'}));
    if (saved.saving === 'disabled') results.append(node('p', m.saving_disabled, {class: 'gap'}));
    if (saved.saving === 'unloaded') results.append(node('p', m.saving_unloaded, {class: 'gap'}));
    results.append(this.time(m.latest_scan, latest.scanned_at));
    if (saved.baseline) results.append(this.time(m.reviewed_scan, saved.baseline.scanned_at));
    const comparison = saved.comparison;
    let state = m.no_baseline;
    if (saved.reviewed) state = m.reviewed;
    else if (comparison) state = comparison.changed ? m.changed : m.unchanged;
    results.append(node('p', state, {class: 'state'}));
    if (comparison?.rules_changed) results.append(node('p', m.rules_changed, {class: 'gap'}));
    for (const limit of comparison?.limits || []) results.append(node('p', limit, {class: 'gap'}));
    if (saved.reviewable) {
      results.append(node('p', m.review_detail),
        this.button(m.review, 'review', () => this.review(), this.busy || offline));
    }
    // A limit alone (such as new rules) is a change with no list to show.
    const changes = comparison?.changed ? this.changes(comparison) : null;
    if (changes) results.append(changes);
    if (latest.bytecode.length) {
      const bytecode = node('section', null, {'aria-labelledby': 'list-bytecode'});
      bytecode.append(this.paths('bytecode', `${m.bytecode} (${latest.bytecode.length})`,
        latest.bytecode, m.bytecode_note));
      results.append(bytecode);
    }
    const details = node('details');
    // With no changes to read first, the full result is the first view.
    details.open = this.full ?? !changes;
    details.addEventListener('toggle', () => { this.full = details.open; });
    details.append(node('summary', m.full_results, {id: 'full'}), this.report(report));
    results.append(details);
    return results;
  }
  changes(comparison) {
    const m = this.messages;
    const section = node('section', null, {'aria-labelledby': 'changes'});
    section.append(node('h3', m.changes, {id: 'changes'}));
    const unproven = comparison.unproven ? m.unproven : null;
    // Added items are positions in the latest report, so each item is sent once.
    const report = this.saved.latest.report;
    const added = kind => comparison.added[kind].map(index => report[kind][index]);
    for (const [id, title, values, note] of [
      ['added-findings', m.added_findings, added('findings'), null],
      ['removed-findings', m.removed_findings, comparison.removed.findings, unproven],
      ['added-capabilities', m.added_capabilities, added('capabilities'), null],
      ['removed-capabilities', m.removed_capabilities, comparison.removed.capabilities, unproven],
    ]) {
      if (values.length) section.append(this.list(id, title, values, id.endsWith('findings'), note, null, 'h4'));
    }
    const files = comparison.files, bytecode = comparison.bytecode;
    const any = values => Object.values(values).some(paths => paths.length);
    if (any(files)) section.append(node('p', m.files_note));
    for (const [id, title, values] of [
      ['files-added', m.files_added, files.added],
      ['files-removed', m.files_removed, files.removed],
      ['files-changed', m.files_changed, files.changed],
      ['bytecode-added', m.bytecode_added, bytecode.added],
      ['bytecode-removed', m.bytecode_removed, bytecode.removed],
      ['bytecode-changed', m.bytecode_changed, bytecode.changed],
    ]) {
      if (values.length) section.append(this.paths(id, `${title} (${values.length})`, values, null, 'h4'));
    }
    return section.childElementCount > 1 ? section : null;
  }
  report(report) {
    const m = this.messages, full = node('div');
    if (!report.complete) full.append(node('p', m.incomplete, {class: 'gap'}));
    const coverage = node('section', null, {'aria-label': m.coverage});
    coverage.append(node('h3', m.coverage));
    for (const check of report.checks) {
      coverage.append(node('p', `${check.name}: ${check.status}`));
      for (const problem of check.problems) {
        coverage.append(node('p', problem.message, {class: 'gap'}));
        if (problem.location) coverage.append(node('code', problem.location, {dir: 'ltr'}));
      }
    }
    full.append(coverage,
      this.list('findings', m.findings, report.findings, true, null, m.no_findings),
      this.list('capabilities', m.capabilities, report.capabilities, false, null, m.no_capabilities));
    return full;
  }
  more(id, total) {
    const shown = this.counts[id] || PAGE;
    const button = total > shown ? this.button(this.messages.more, `more-${id}`, () => {
      this.counts[id] = shown + PAGE;
      this.render();
      this.shadowRoot.getElementById(`list-${id}`).focus();
    }) : null;
    return [shown, button ? [button] : []];
  }
  list(id, title, values, findings, note = null, empty = null, level = 'h3') {
    const m = this.messages, [shown, more] = this.more(id, values.length);
    const section = node('section', null, {'aria-labelledby': `list-${id}`});
    section.append(node(level, `${title} (${values.length})`, {id: `list-${id}`, tabindex: '-1'}));
    if (note) section.append(node('p', note, {class: 'gap'}));
    if (!values.length && empty) section.append(node('p', empty));
    for (const item of values.slice(0, shown)) {
      const article = node('article');
      if (findings) article.append(node('strong', item.label, {class: `severity ${item.severity}`}));
      article.append(node('p', item.message), node('code', item.location, {dir: 'ltr'}));
      if (item.action) article.append(node('p', item.action));
      if (findings) {
        const details = node('details');
        details.append(node('summary', m.technical), node('code', item.rule, {dir: 'ltr'}),
          node('p', item.confidence));
        if (item.detail) details.append(node('p', item.detail));
        if (item.evidence) details.append(node('h4', m.evidence), node('pre', item.evidence, {dir: 'ltr'}));
        article.append(details);
      }
      section.append(article);
    }
    section.append(...more);
    return section;
  }
  paths(id, title, values, note = null, level = 'h3') {
    const [shown, more] = this.more(id, values.length);
    const section = node('div', null, {class: 'paths'});
    section.append(node(level, title, {id: `list-${id}`, tabindex: '-1'}));
    if (note) section.append(node('p', note));
    const list = node('ul');
    for (const path of values.slice(0, shown)) {
      const item = node('li');
      item.append(node('code', path, {dir: 'ltr'}));
      list.append(item);
    }
    section.append(list, ...more);
    return section;
  }
}
if (!customElements.get('doorcheck-panel')) customElements.define('doorcheck-panel', DoorcheckPanel);
