// Native light-dismiss where available; keep older browsers on the same interaction contract.
if (!("closedBy" in HTMLDialogElement.prototype)) {
  for (const dialog of document.querySelectorAll('dialog[closedby="any"]')) {
    let pointer = null;
    const outside = event => {
      const r = dialog.getBoundingClientRect();
      return event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom;
    };
    dialog.addEventListener("pointerdown", event => {
      pointer = event.isPrimary && event.button === 0 && outside(event) ? event.pointerId : null;
    });
    dialog.addEventListener("pointerup", event => {
      if (pointer === event.pointerId && outside(event)) dialog.close();
      pointer = null;
    });
    for (const type of ["pointercancel", "close"]) dialog.addEventListener(type, () => { pointer = null; });
  }
}
