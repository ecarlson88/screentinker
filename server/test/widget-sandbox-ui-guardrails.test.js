'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SETTINGS = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'js', 'views', 'settings.js'), 'utf8');
const APP = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'js', 'app.js'), 'utf8');

test('settings modal requires the exact confirmation phrase before disable submit enables', () => {
  assert.match(SETTINGS, /Disable widget sandbox isolation for this organization/);
  assert.match(SETTINGS, /Type the phrase below to confirm:/);
  assert.match(SETTINGS, /I understand I am enabling a security hole/);
  assert.match(
    SETTINGS,
    /submit\.disabled\s*=\s*input\.value\.trim\(\)\s*!==\s*confirmationPhrase/,
    'confirm button must stay disabled until exact phrase match (trimmed only)'
  );
});

test('dashboard warning banner renders when org isolation is disabled and links to settings', () => {
  assert.match(APP, /widgetSandboxWarningBanner/);
  assert.match(APP, /Widget sandbox isolation is DISABLED\./);
  assert.match(APP, /Re-enable in Settings > Security\./);
  assert.match(APP, /link\.href = '#\/settings'/);
});
