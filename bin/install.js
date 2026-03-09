#!/usr/bin/env node
const { execSync, spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const venvPath = path.join(__dirname, '..', '.venv');
const reqPath = path.join(__dirname, '..', 'requirements.txt');

try {
    if (!fs.existsSync(venvPath)) {
        console.log('Creating Python virtual environment...');
        // Try python3 first, fallback to python
        try {
            execSync('python3 -m venv .venv', {
                cwd: path.join(__dirname, '..'),
                stdio: 'inherit'
            });
        } catch (e) {
            execSync('python -m venv .venv', {
                cwd: path.join(__dirname, '..'),
                stdio: 'inherit'
            });
        }
    } else {
        console.log('Python virtual environment already exists.');
    }

    const pipCmd = process.platform === 'win32'
        ? path.join(venvPath, 'Scripts', 'pip')
        : path.join(venvPath, 'bin', 'pip');

    console.log('Installing Python dependencies...');
    const pipArgs = ['install', '-r', reqPath];
    const result = spawnSync(pipCmd, pipArgs, {
        cwd: path.join(__dirname, '..'),
        stdio: 'inherit'
    });

    if (result.error || result.status !== 0) {
        throw new Error(`pip install failed with status ${result.status}`);
    }
    console.log('Installation complete.');
} catch (error) {
    console.error('Failed to setup Python environment:', error.message);
    process.exit(1);
}
