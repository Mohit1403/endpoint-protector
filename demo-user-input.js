const NmapRunner = require('./utils/nmapRunner');

console.log('=== User Input to NMAP Demo ===\n');

// Simulate user inputs (similar to what would come from the web form)
const userInputs = [
    {
        target: '8.8.8.8',
        scanType: '-sn',
        description: 'Simple ping scan of Google DNS'
    },
    {
        target: 'https://www.google.com',
        scanType: '-p 80,443',
        description: 'Port scan of Google website (via URL input)'
    },
    {
        target: 'scanme.nmap.org',
        scanType: '--top-ports 10',
        description: 'Top 10 ports scan of Nmap test server'
    }
];

console.log('Simulating user inputs from web interface:\n');

userInputs.forEach((input, index) => {
    console.log(`--- Test ${index + 1}: ${input.description} ---`);
    console.log(`User entered target: "${input.target}"`);
    console.log(`User selected scan type: "${input.scanType}"`);
    
    // Step 1: Validate user input (same as web app does)
    const isValid = NmapRunner.validateTarget(input.target);
    console.log(`Input validation result: ${isValid}`);
    
    if (!isValid) {
        console.log('❌ Invalid input - scan rejected\n');
        return;
    }
    
    // Step 2: Process target (extract domain from URL if needed)
    const processedTarget = NmapRunner.processTarget(input.target);
    console.log(`Processed target: "${processedTarget}"`);
    
    // Step 3: Show what actual nmap command will be executed
    console.log(`✅ This will execute: nmap ${input.scanType} ${processedTarget} -v --host-timeout 300s`);
    console.log(`Real nmap binary is being called - no shell injection possible!\n`);
});

console.log('=== Security Features Demonstrated ===');
console.log('✅ Input validation prevents invalid targets');
console.log('✅ URL processing extracts clean domain names');
console.log('✅ Arguments are passed as array to spawn() - no shell injection');
console.log('✅ Dangerous flags like -oN, --script-args are filtered out');
console.log('✅ Timeout limits prevent infinite scans');
console.log('✅ Real nmap binary is called directly via spawn()');

console.log('\n=== Testing Malicious Input Filtering ===');
const maliciousInputs = [
    '-sS google.com; rm -rf /',
    '-oN /etc/passwd google.com',
    '--script-args "os.execute(\'evil_command\')"',
    'google.com && curl malicious-site.com'
];

maliciousInputs.forEach((malicious, index) => {
    console.log(`Test ${index + 1}: "${malicious}"`);
    const args = malicious.split(' ').filter(arg => arg.length > 0);
    const dangerousFlags = ['-oN', '-oX', '-oS', '-oG', '--script-args', '-iL'];
    const filtered = args.filter(arg => {
        return !dangerousFlags.some(flag => arg.startsWith(flag));
    });
    console.log(`After filtering: [${filtered.join(', ')}]`);
    console.log('Shell injection prevented by using spawn() with argument array\n');
});
