'use strict';

const fs = require('fs');
const path = require('path');

const AUDIT_PATH = process.env.AUDIT_LOG_PATH || '/audit/audit.log';

function audit(event, meta, extra) {
  const line = JSON.stringify(
    Object.assign({ event, at: new Date().toISOString() }, meta || {}, extra || {})
  );

  try {
    console.log(`[audit] ${line}`);
  } catch (e) {
    // ignore
  }

  try {
    fs.mkdirSync(path.dirname(AUDIT_PATH), { recursive: true });
    fs.appendFileSync(AUDIT_PATH, `${line}\n`, 'utf8');
  } catch (e) {
    // read-only / disk full: keep the app alive
  }

  return line;
}

module.exports = audit;