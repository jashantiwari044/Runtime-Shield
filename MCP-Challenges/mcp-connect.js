const { spawn } = require('child_process');

if (process.argv.length < 4) {
    console.error('Usage: node mcp-connect.js <host> <port>');
    process.exit(1);
}

const host = process.argv[2];
const port = process.argv[3];

// Use ncat as the underlying connection tool
const ncat = spawn('ncat', [host, port], { stdio: ['pipe', 'pipe', 'inherit'] });

let bannerStripped = false;

ncat.stdout.on('data', (data) => {
    if (!bannerStripped) {
        const text = data.toString();
        // Check if the current chunk starts with the kCTF banner
        if (text.startsWith('== proof-of-work:')) {
            const lines = text.split('\n');
            lines.shift(); // Remove the first line
            bannerStripped = true;
            if (lines.length > 0) {
                process.stdout.write(lines.join('\n'));
            }
        } else {
            // No banner found in the first chunk, just pass through
            bannerStripped = true;
            process.stdout.write(data);
        }
    } else {
        process.stdout.write(data);
    }
});

process.stdin.on('data', (data) => {
    ncat.stdin.write(data);
});

ncat.on('close', (code) => {
    process.exit(code);
});

ncat.on('error', (err) => {
    console.error('Failed to start ncat:', err);
    process.exit(1);
});
