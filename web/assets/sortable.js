export function makeSortableTable(table, tbody, rowsOf, opts = {}) {
  const headers = Array.from(table.querySelectorAll('thead th[data-sort]'));
  let key = opts.defaultKey || (headers[0] && headers[0].dataset.sort);
  let dir = opts.defaultDir || 'asc';

  const render = () => {
    headers.forEach(th => {
      const k = th.dataset.sort;
      th.classList.toggle('sort-asc', k === key && dir === 'asc');
      th.classList.toggle('sort-desc', k === key && dir === 'desc');
    });
    tbody.innerHTML = '';
    for (const tr of rowsOf(key, dir)) tbody.appendChild(tr);
  };

  for (const th of headers) {
    th.classList.add('sortable');
    th.addEventListener('click', () => {
      const k = th.dataset.sort;
      if (k === key) {
        dir = dir === 'asc' ? 'desc' : 'asc';
      } else {
        key = k;
        dir = 'asc';
      }
      render();
    });
  }
  render();
}
