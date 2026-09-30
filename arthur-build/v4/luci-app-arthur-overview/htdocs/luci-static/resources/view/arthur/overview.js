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
const callSystemInfo = rpc.declare({
	object: 'system', method: 'info', expect: { }
});

function readStatus(call) {
	return Promise.resolve().then(call).catch(function() { return null; });
}

function fetchStatus() {
	return Promise.all([
		readStatus(function() { return callMwan('interfaces'); }),
		readStatus(callInterfaces),
		readStatus(callWireless),
		readStatus(callSystemInfo)
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
			status = ({ online: '在线', offline: '离线', disabled: '已停用',
				unknown: '未知' })[status] || status;
			rows.push(E('li', {}, [ name + '：', status ]));
		});
	}
	if (!rows.length) {
		let count = interfaces && Array.isArray(interfaces.interface)
			? interfaces.interface.filter(i => i && i.interface && /^wan/.test(i.interface)).length : 0;
		let message = count ? '已发现 WAN 接口，mwan3 暂未返回线路健康状态'
			: mwan == null || !interfaces || !Array.isArray(interfaces.interface)
				? '双 WAN 状态读取不可用，无法判断线路配置'
				: '尚未发现 WAN 接口或 mwan3 线路状态';
		rows.push(E('li', {}, message));
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
		E('p', {}, wireless == null ? '无线状态读取不可用，无法判断 Mesh 配置'
			: meshCount ? '已配置 Mesh 接口：' + meshCount : '目前未发现 Mesh 接口'),
		[ 'admin', 'status', 'overview' ], '查看系统状态');
}

function nonnegative(value) {
	return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function systemPanel(info) {
	let rows = [];
	if (info && nonnegative(info.uptime)) {
		let seconds = Math.floor(info.uptime);
		rows.push(E('li', {}, '运行时间：' + Math.floor(seconds / 86400) + ' 天 '
			+ Math.floor(seconds % 86400 / 3600) + ' 时 '
			+ Math.floor(seconds % 3600 / 60) + ' 分 ' + seconds % 60 + ' 秒'));
	}
	if (info && Array.isArray(info.load) && info.load.length === 3 && info.load.every(nonnegative))
		rows.push(E('li', {}, '系统负载（1/5/15 分钟）：' + info.load.map(n => (n / 65535).toFixed(2)).join(' / ')));
	let memory = info && info.memory;
	if (memory && nonnegative(memory.total) && memory.total > 0) {
		rows.push(E('li', {}, '系统可用内存总量：' + (memory.total / 1048576).toFixed(1) + ' MiB'));
		rows.push(E('li', {}, '当前可分配内存：' + (nonnegative(memory.available) && memory.available <= memory.total
			? (memory.available / 1048576).toFixed(1) + ' MiB' : '未提供')));
	}
	if (!rows.length)
		rows.push(E('li', {}, '系统状态读取不可用，无法显示内存和负载'));
	rows.push(E('li', {}, 'NSS/ECM 加速：待实机计数器和吞吐测试验证'));
	return section('NSS 与系统状态', '显示系统实际报告的数据；内存总量不包含硬件保留区域，不能据此判断硬改容量。',
		E('ul', {}, rows));
}

function renderPanels(data) {
	return [
		wanPanel(data[0], data[1]),
		meshPanel(data[2]),
		systemPanel(data[3]),
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
