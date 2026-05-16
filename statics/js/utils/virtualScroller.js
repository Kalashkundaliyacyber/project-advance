/**
 * ScanWise AI — Virtual Scroller
 * Renders only visible rows of large vulnerability lists to prevent
 * browser memory spikes on scans with 100+ findings.
 *
 * Why this matters:
 *   Without virtualization, rendering 200+ vulnerability cards can consume
 *   100–300MB of DOM memory and freeze the UI for 2–5 seconds.
 *   Virtual rendering keeps DOM nodes to ~20 regardless of list size.
 *
 * Usage:
 *   const scroller = VirtualScroller.create(container, items, renderFn, rowHeight);
 *   scroller.update(newItems);  // replace items
 *   scroller.destroy();         // clean up
 */
const VirtualScroller = (() => {
  const DEFAULT_ROW_HEIGHT = 120;   // px — approximate height of one vuln card
  const OVERSCAN           = 3;     // render N rows above/below visible area

  /**
   * Create a virtual scroller for a container.
   * @param {HTMLElement} container  - scroll container (overflow-y: auto)
   * @param {Array}       items      - full data array
   * @param {Function}    renderFn   - (item, index) => HTMLElement
   * @param {number}      rowHeight  - approximate row height in px
   */
  function create(container, items, renderFn, rowHeight = DEFAULT_ROW_HEIGHT) {
    let _items     = items.slice();
    let _rowHeight = rowHeight;

    // Spacer elements to maintain scroll height without rendering all rows
    const topSpacer    = document.createElement('div');
    const bottomSpacer = document.createElement('div');
    const viewport     = document.createElement('div');
    viewport.style.cssText = 'position:relative';
    container.appendChild(topSpacer);
    container.appendChild(viewport);
    container.appendChild(bottomSpacer);

    let _rendered = { start: 0, end: 0 };

    function _render() {
      const scrollTop    = container.scrollTop;
      const visibleHeight = container.clientHeight || 600;
      const total        = _items.length;

      const startIdx = Math.max(0, Math.floor(scrollTop / _rowHeight) - OVERSCAN);
      const endIdx   = Math.min(total, Math.ceil((scrollTop + visibleHeight) / _rowHeight) + OVERSCAN);

      if (startIdx === _rendered.start && endIdx === _rendered.end) return;
      _rendered = { start: startIdx, end: endIdx };

      topSpacer.style.height    = `${startIdx * _rowHeight}px`;
      bottomSpacer.style.height = `${Math.max(0, (total - endIdx) * _rowHeight)}px`;

      // Clear and re-render visible slice
      viewport.innerHTML = '';
      const frag = document.createDocumentFragment();
      for (let i = startIdx; i < endIdx; i++) {
        try {
          const el = renderFn(_items[i], i);
          if (el) frag.appendChild(el);
        } catch (err) {
          console.warn('VirtualScroller render error at index', i, err);
        }
      }
      viewport.appendChild(frag);
    }

    const _onScroll = () => requestAnimationFrame(_render);
    container.addEventListener('scroll', _onScroll, { passive: true });
    _render();

    return {
      /** Replace the item list and re-render. */
      update(newItems) {
        _items = newItems.slice();
        _rendered = { start: -1, end: -1 };   // force re-render
        _render();
      },
      /** Force a re-render (e.g. after container resize). */
      refresh() {
        _rendered = { start: -1, end: -1 };
        _render();
      },
      /** Remove event listeners and clear DOM. */
      destroy() {
        container.removeEventListener('scroll', _onScroll);
        topSpacer.remove();
        bottomSpacer.remove();
        viewport.remove();
      },
      get itemCount() { return _items.length; },
    };
  }

  return { create };
})();
