// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// NikBel0x ヽ(*・ω・)ﾉ
// Julia L.
// Review: Vadim S.

const requestPin = (title, message) => new Promise((resolve, reject) => {
  if (document.getElementById('pin-prompt')) {
    reject(new Error('PIN entry already open'));
    return;
  }
  const previous = document.activeElement;
  const overlay = document.createElement('div');
  const box = document.createElement('form');
  const heading = document.createElement('h2');
  const detail = document.createElement('p');
  const group = document.createElement('div');
  const label = document.createElement('label');
  const row = document.createElement('div');
  const input = document.createElement('input');
  const buttons = document.createElement('div');
  const cancel = document.createElement('button');
  const confirm = document.createElement('button');
  overlay.id = 'pin-prompt';
  overlay.className = 'modal-bg show';
  box.className = 'modal-box';
  box.setAttribute('role', 'dialog');
  box.setAttribute('aria-modal', 'true');
  box.setAttribute('aria-labelledby', 'pin-title');
  box.setAttribute('aria-describedby', 'pin-message');
  heading.id = 'pin-title';
  heading.textContent = title;
  detail.id = 'pin-message';
  detail.className = 'confirm-detail';
  detail.style.overflowWrap = 'anywhere';
  detail.style.whiteSpace = 'pre-wrap';
  detail.style.textTransform = 'none';
  detail.textContent = message;
  group.className = 'input-group';
  label.htmlFor = 'sign-pin';
  label.textContent = 'PIN';
  row.className = 'input-row';
  input.id = 'sign-pin';
  input.type = 'password';
  input.autocomplete = 'off';
  input.required = true;
  input.style.minWidth = '0';
  buttons.className = 'modal-btns';
  cancel.className = 'btn-cancel';
  cancel.type = 'button';
  cancel.textContent = 'cancel';
  confirm.className = 'btn-confirm';
  confirm.type = 'submit';
  confirm.textContent = 'sign';
  let closed = false;
  const close = value => {
    if (closed) return;
    closed = true;
    input.value = '';
    document.removeEventListener('keydown', keydown, true);
    window.removeEventListener('pagehide', leave);
    overlay.remove();
    if (previous && previous.isConnected) previous.focus();
    resolve(value);
  };
  const leave = () => close(null);
  const keydown = event => {
    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      close(null);
    } else if (event.key === 'Tab') {
      const fields = [input, cancel, confirm];
      const current = fields.indexOf(document.activeElement);
      const next = current < 0 ? 0 : (current + (event.shiftKey ? 2 : 1)) % 3;
      event.preventDefault();
      fields[next].focus();
    }
  };
  box.addEventListener('submit', event => {
    event.preventDefault();
    if (input.value.length) close(input.value);
    else input.focus();
  });
  cancel.addEventListener('click', leave);
  overlay.addEventListener('click', event => {
    if (event.target === overlay) close(null);
  });
  document.addEventListener('keydown', keydown, true);
  window.addEventListener('pagehide', leave);
  row.append(input);
  group.append(label, row);
  buttons.append(cancel, confirm);
  box.append(heading, detail, group, buttons);
  overlay.append(box);
  document.body.append(overlay);
  input.focus();
});

const pinCall = async (send, body, message) => {
  const approved = JSON.parse(JSON.stringify(body));
  const session = Object.freeze({...await send('GET', '/wallet/session')});
  if (!session.address || !/^[0-9]+$/.test(String(session.generation)))
    throw new Error('wallet session unavailable');
  const pin = await requestPin('authorize transaction', message + '\nwallet: ' + session.address);
  if (!pin) throw new Error('transaction cancelled before signing');
  return send('POST', '/contract/call', { ...approved, pin }, session);
};