const NmapRunner = require('./utils/nmapRunner');

console.log('=== NMAP Integration Test ===\n');

// Test 1: Input validation
console.log('Test 1: Input Validation');
console.log('Valid IP (8.8.8.8):', NmapRunner.validateTarget('8.8.8.8'));
console.log('Valid domain (google.com):', NmapRunner.validateTarget('google.com'));
console.log('Valid URL (https://google.com):', NmapRunner.validateTarget('https://google.com'));
console.log('Invalid target (invalid):', NmapRunner.validateTarget('invalid'));
console.log('Empty target:', NmapRunner.validateTarget(''));

console.log('\nTest 2: Target Processing');
console.log('IP address (8.8.8.8):', NmapRunner.processTarget('8.8.8.8'));
console.log('Domain (google.com):', NmapRunner.processTarget('google.com'));
console.log('URL (https://www.google.com):', NmapRunner.processTarget('https://www.google.com'));
console.log('URL (http://google.com):', NmapRunner.processTarget('http://google.com'));

console.log('\nTest 3: Command Execution (ping scan of localhost)');
// Test a simple ping scan of localhost - this should be safe and fast
NmapRunner.executeScan('127.0.0.1', '-sn', '', (error, result) => {
    if (error && !result) {
        console.error('Error:', error);
        return;
    }
    
    if (result) {
        switch(result.type) {
            case 'stdout':
                console.log('[STDOUT]', result.data.trim());
                break;
            case 'stderr':
                console.log('[STDERR]', result.data.trim());
                break;
            case 'complete':
                console.log('[COMPLETE] Scan finished with exit code:', result.exitCode);
                console.log('Full output length:', result.data.length, 'characters');
                break;
            case 'error':
                console.log('[ERROR] Scan failed with exit code:', result.exitCode);
                console.log('Error output:', result.data);
                break;
        }
    }
});

console.log('\nTest initiated. Real nmap execution will show above...\n');
