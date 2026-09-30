'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname,
  'luci-app-arthur-overview/htdocs/luci-static/resources/view/arthur/overview.js'), 'utf8');

// Exercise the whole LuCI view with changing ubus replies and a minimal DOM.
function harness(replies) {
  const calls = [];
  const notifications = [];
  function E(tag, attrs, children) {
    return {
      tag, attrs, children: Array.isArray(children) ? children : [children],
      addEventListener(event, callback) { this[event] = callback; },
      replaceChildren(...next) { this.children = next; }
    };
  }
  const context = {
    E, L: { url: (...parts) => '/' + parts.join('/') },
    ui: { addNotification: (...args) => notifications.push(args) },
    view: { extend: value => value },
    rpc: { declare: ({ object, method }) => (...args) => {
      const key = object + '.' + method;
      calls.push([key, args]);
      const reply = replies[key];
      if (reply instanceof Error) return Promise.reject(reply);
      return typeof reply === 'function' ? reply() : Promise.resolve(reply);
    } }
  };
  return { page: vm.runInNewContext('(function() {\n' + source + '\n})()', context),
    calls, notifications };
}

function text(node) {
  if (node == null) return '';
  if (typeof node !== 'object') return String(node);
  return node.children.map(text).join('\n');
}

function replies() {
  return {
    'mwan3.status': { interfaces: { wan: { status: 'online' }, wan2: { status: 'offline' } } },
    'network.interface.dump': { interface: [{ interface: 'wan' }, { interface: 'wan2' }] },
    'network.wireless.status': { radio0: { interfaces: [{ config: { mode: 'mesh' } }] } },
    'system.info': { uptime: 90061, load: [65535, 131070, 0],
      memory: { total: 960 * 1048576, available: 512 * 1048576 } }
  };
}

test('real ubus data renders units and independent WAN health without claiming acceleration', async () => {
  const h = harness(replies());
  const output = text(h.page.render(await h.page.load()));
  assert.match(output, /wan：\n在线/);
  assert.match(output, /wan2：\n离线/);
  assert.match(output, /已配置 Mesh 接口：1/);
  assert.match(output, /1 天 1 时 1 分 1 秒/);
  assert.match(output, /1\.00 \/ 2\.00 \/ 0\.00/);
  assert.match(output, /960\.0 MiB/);
  assert.match(output, /512\.0 MiB/);
  assert.match(output, /NSS\/ECM 加速：待实机/);
  assert.deepEqual(h.calls.map(([key]) => key).sort(),
    ['mwan3.status', 'network.interface.dump', 'network.wireless.status', 'system.info']);
});

test('all denied RPCs show unavailable rather than absence', async () => {
  const r = replies();
  for (const key of Object.keys(r)) r[key] = new Error('access denied');
  const h = harness(r);
  const output = text(h.page.render(await h.page.load()));
  assert.match(output, /双 WAN 状态读取不可用/);
  assert.match(output, /无线状态读取不可用/);
  assert.match(output, /系统状态读取不可用/);
  assert.doesNotMatch(output, /目前未发现 Mesh 接口/);
});

test('one failed service does not hide successful system and wireless data', async () => {
  const r = replies();
  r['mwan3.status'] = new Error('service unavailable');
  const h = harness(r);
  const output = text(h.page.render(await h.page.load()));
  assert.match(output, /已发现 WAN 接口，mwan3 暂未返回线路健康状态/);
  assert.match(output, /已配置 Mesh 接口：1/);
  assert.match(output, /512\.0 MiB/);
});

test('successful empty wireless and WAN replies remain distinct from errors', async () => {
  const r = replies();
  r['mwan3.status'] = { interfaces: {} };
  r['network.interface.dump'] = { interface: [] };
  r['network.wireless.status'] = {};
  const h = harness(r);
  const output = text(h.page.render(await h.page.load()));
  assert.match(output, /尚未发现 WAN 接口或 mwan3 线路状态/);
  assert.match(output, /目前未发现 Mesh 接口/);
  assert.doesNotMatch(output, /读取不可用/);
});

test('zero uptime and available memory are valid, missing availability is not invented', async () => {
  const r = replies();
  r['system.info'] = { uptime: 0, load: [0, 0, 0], memory: { total: 1048576, available: 0 } };
  const h = harness(r);
  let output = text(h.page.render(await h.page.load()));
  assert.match(output, /0 天 0 时 0 分 0 秒/);
  assert.match(output, /当前可分配内存：0\.0 MiB/);
  delete r['system.info'].memory.available;
  output = text(h.page.render(await h.page.load()));
  assert.match(output, /当前可分配内存：未提供/);
});

test('invalid metrics cannot become NaN, infinity or negative memory figures', async () => {
  const r = replies();
  r['system.info'] = { uptime: -1, load: [NaN, Infinity, -1], memory: { total: -1 } };
  const h = harness(r);
  const output = text(h.page.render(await h.page.load()));
  assert.match(output, /系统状态读取不可用/);
  assert.doesNotMatch(output, /NaN|Infinity|-1/);
  r['system.info'] = { memory: { total: 1048576, available: 2 * 1048576 } };
  assert.match(text(h.page.render(await h.page.load())), /当前可分配内存：未提供/);
});

test('refresh replaces stale successful state with failure and re-enables the button', async () => {
  const r = replies();
  const h = harness(r);
  const root = h.page.render(await h.page.load());
  const refresh = root.children[2];
  r['network.wireless.status'] = () => { throw new Error('synchronous RPC failure'); };
  r['system.info'] = new Error('disconnected');
  refresh.click();
  assert.equal(refresh.disabled, true);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(refresh.disabled, false);
  assert.match(text(root), /无线状态读取不可用/);
  assert.match(text(root), /系统状态读取不可用/);
  assert.doesNotMatch(text(root), /已配置 Mesh 接口：1|512\.0 MiB/);
  assert.equal(h.notifications.length, 0);
});
