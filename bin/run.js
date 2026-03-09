#!/usr/bin/env node
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const venvPath = path.join(__dirname, '..', '.venv');
const pythonCmd = process.platform === 'win32'
    ? path.join(venvPath, 'Scripts', 'python')
    : path.join(venvPath, 'bin', 'python');

if (!fs.existsSync(pythonCmd)) {
    console.error(`Error: Python executable not found at ${pythonCmd}`);
    console.error('The virtual environment may not have been created correctly.');
    console.error('Try running: npm run postinstall');
    process.exit(1);
}

const args = ['-m', 'mesh_pulse', ...process.argv.slice(2)];

// TUI apps need stdin, stdout, and stderr as raw context usually. 
// stdio: "inherit" passes through perfectly to Textual/Rich.
const result = spawnSync(pythonCmd, args, {
    cwd: process.cwd(),
    stdio: 'inherit'
});

if (result.error) {
    console.error(`Failed to launch mesh_pulse: ${result.error.message}`);
    process.exit(1);
}

process.exit(result.status !== null ? result.status : 1);
