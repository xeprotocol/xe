const NS = 'http://www.w3.org/2000/svg';
const W = 480;
const H = 120;
const PAD = 10;

function el(name, attrs = {}) {
  const e = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
  return e;
}

function svgRoot() {
  return el('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none' });
}

function placeholder(text) {
  const svg = svgRoot();
  const t = el('text', { x: W / 2, y: H / 2 + 4, 'text-anchor': 'middle', 'font-size': 11, fill: '#666' });
  t.textContent = text;
  svg.appendChild(t);
  const wrap = document.createElement('div');
  wrap.className = 'chart-wrap';
  wrap.appendChild(svg);
  return wrap;
}

function chartWrap(svg, yMax) {
  const wrap = document.createElement('div');
  wrap.className = 'chart-wrap';
  wrap.appendChild(svg);
  const top = document.createElement('span');
  top.className = 'chart-axis chart-axis-top';
  top.textContent = String(yMax);
  wrap.appendChild(top);
  const bot = document.createElement('span');
  bot.className = 'chart-axis chart-axis-bot';
  bot.textContent = '0';
  wrap.appendChild(bot);
  return wrap;
}

function baseline(svg) {
  svg.appendChild(el('line', {
    x1: PAD, y1: H - PAD, x2: W - PAD, y2: H - PAD,
    stroke: 'rgba(192,198,207,0.2)', 'stroke-width': 1, 'vector-effect': 'non-scaling-stroke',
  }));
}

export function lineChart(samples, opts = {}) {
  const { color = '#ff7300' } = opts;
  if (!samples || samples.length < 2) return placeholder('not enough data');

  const xs = samples.map(s => s.x);
  const ys = samples.map(s => s.y);
  const xMin = Math.min(...xs);
  const xMax = Math.max(...xs);
  const yMin = 0;
  const yMax = Math.max(1, Math.max(...ys));
  const xR = xMax - xMin || 1;
  const yR = yMax - yMin || 1;
  const sx = v => PAD + ((v - xMin) / xR) * (W - 2 * PAD);
  const sy = v => H - PAD - ((v - yMin) / yR) * (H - 2 * PAD);

  const svg = svgRoot();
  baseline(svg);
  const path = samples.map((s, i) => `${i === 0 ? 'M' : 'L'} ${sx(s.x).toFixed(1)} ${sy(s.y).toFixed(1)}`).join(' ');
  svg.appendChild(el('path', { d: path, fill: 'none', stroke: color, 'stroke-width': 1.5, 'stroke-linejoin': 'round', 'vector-effect': 'non-scaling-stroke' }));

  const last = samples[samples.length - 1];
  svg.appendChild(el('circle', { cx: sx(last.x), cy: sy(last.y), r: 2.5, fill: color }));

  return chartWrap(svg, yMax);
}

export function sparkline(values, opts = {}) {
  const w = 120;
  const h = 28;
  const { color = '#ff7300', fill = 'rgba(255,115,0,0.10)' } = opts;
  const svg = el('svg', { viewBox: `0 0 ${w} ${h}`, preserveAspectRatio: 'none' });
  if (!values || values.length < 2) return svg;
  const yMin = Math.min(...values);
  const yMax = Math.max(...values);
  const yR = yMax - yMin || 1;
  const sx = i => (i / (values.length - 1)) * w;
  const sy = v => h - 2 - ((v - yMin) / yR) * (h - 4);

  const points = values.map((v, i) => `${sx(i).toFixed(1)},${sy(v).toFixed(1)}`).join(' ');
  const areaPath = `M 0 ${h} L ${points.replaceAll(' ', ' L ')} L ${w} ${h} Z`;
  svg.appendChild(el('path', { d: areaPath, fill }));
  svg.appendChild(el('polyline', { points, fill: 'none', stroke: color, 'stroke-width': 1.25 }));
  return svg;
}

export function barChart(values, opts = {}) {
  const { color = '#ff7300' } = opts;
  if (!values || values.length === 0) return placeholder('no data');

  const yMax = Math.max(1, ...values);
  const barW = (W - 2 * PAD) / values.length;
  const svg = svgRoot();
  baseline(svg);

  values.forEach((v, i) => {
    const h = (v / yMax) * (H - 2 * PAD);
    if (h <= 0) return;
    svg.appendChild(el('rect', {
      x: PAD + i * barW,
      y: H - PAD - h,
      width: Math.max(0.5, barW - 1),
      height: h,
      fill: color,
    }));
  });

  return chartWrap(svg, yMax);
}
