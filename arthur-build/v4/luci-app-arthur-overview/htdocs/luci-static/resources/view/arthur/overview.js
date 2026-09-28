'use strict';
'require rpc';
'require view';
'require ui';

const callMwan = rpc.declare({
	object: 'mwan3', method: 'status', params: [ 'section' ], expect: { }
});
const callInterfaces = rpc.declare({
	object: 'network.interface', method: 'dump', expect: { }
});
const callWireless = rpc.declare({
	object: 'network.wireless', method: 'status', expect: { }
});

function fetchStatus() {
	return Promise.all([
		L.resolveDefault(callMwan('interfaces'), {}),
		L.resolveDefault(callInterfaces(), {}),
		L.resolveDefault(callWireless(), {})
	]);
}

function section(title, description, body, link, linkLabel) {
	let children = [ E('h3', {}, title), E('p', {}, description), body ];
	if (link)
		children.push(E('p', {}, E('a', { href: L.url(...link) }, linkLabel)));
	return E('div', { class: 'cbi-section' }, children);
}

function wanPanel(mwan, interfaces) {
	let entries = mwan && mwan.interfaces;
	let rows = [];
	if (entries && typeof entries === 'object') {
		Object.keys(entries).sort().forEach(function(name) {
			let status = entries[name] && entries[name].status || 'unknown';
			rows.push(E('li', {}, [ name + '：', status ]));
		});
	}
	if (!rows.length) {
		let count = interfaces && Array.isArray(interfaces.interface)
			? interfaces.interface.filter(i => i && i.interface && /^wan/.test(i.interface)).length : 0;
		rows.push(E('li', {}, count ? '已发现 WAN 接口，mwan3 状态尚不可用' : '尚未发现可用的双 WAN 状态'));
	}
	return section('双 WAN', '显示线路健康状态；线路比例、故障切换和设备分流需在端口映射验证后配置。',
		E('ul', {}, rows), [ 'admin', 'status', 'mwan3' ], '查看双 WAN 详细状态');
}

function meshPanel(wireless) {
	let meshCount = 0;
	Object.keys(wireless || {}).forEach(function(name) {
		let radio = wireless[name];
		if (radio && Array.isArray(radio.interfaces))
			radio.interfaces.forEach(function(iface) {
				if (iface && iface.config && iface.config.mode === 'mesh') meshCount++;
			});
	});
	return section('Mesh 组网', '显示已配置的 Mesh 无线接口；节点列表和无线回程需实机验证。',
		E('p', {}, meshCount ? '已配置 Mesh 接口：' + meshCount : '目前未发现 Mesh 接口'),
		[ 'admin', 'status', 'overview' ], '查看系统状态');
}

function renderPanels(data) {
	return [
		wanPanel(data[0], data[1]),
		meshPanel(data[2]),
		section('NSS 与系统状态', '有线 NSS/ECM、无线驱动和 1GB 内存需在新固件实机启动后读取。',
			E('p', {}, '运行状态：待实机验证；当前页面不推断硬件加速已生效。')),
		section('Sing-box 核心更新', '独立更新须先完成新固件编译、配置检查、健康检查和回滚。',
			E('p', {}, '更新操作尚未开放'))
	];
}

return view.extend({
	load: fetchStatus,
	render: function(data) {
		let content = E('div', {}, renderPanels(data));
		let refresh = E('button', { class: 'btn cbi-button cbi-button-action' }, '刷新状态');
		refresh.addEventListener('click', function() {
			refresh.disabled = true;
			fetchStatus().then(function(next) {
				content.replaceChildren(...renderPanels(next));
			}).catch(function() {
				ui.addNotification(null, E('p', {}, '状态读取失败，请稍后重试。'));
			}).finally(function() { refresh.disabled = false; });
		});
		return E('div', { class: 'cbi-map' }, [
			E('h2', {}, '亚瑟功能概览'),
			E('p', {}, '当前是只读状态页。设置、升级与核心更新需通过安全检查后开放。'),
			refresh, content
		]);
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
