const { spawn } = require('child_process');

class NmapRunner {
    static executeScan(target, scanType, nseScripts, callback) {
        try {
            // Validate inputs
            if (!target || !scanType) {
                return callback('Target and scan type are required', null);
            }
            
            // Build command arguments array
            let args = scanType.split(' ').filter(arg => arg.length > 0);
            
            // Convert privileged scans to unprivileged alternatives for Windows
            args = this.convertToUnprivilegedScan(args);
            
            // Basic security: remove potentially dangerous flags
            const dangerousFlags = ['-oN', '-oX', '-oS', '-oG', '--script-args', '-iL'];
            args = args.filter(arg => {
                return !dangerousFlags.some(flag => arg.startsWith(flag));
            });
            
            // Add NSE scripts if provided (with validation)
            if (nseScripts && nseScripts.trim()) {
                const scriptArgs = nseScripts.split(' ').filter(arg => arg.length > 0);
                // Only allow --script flags, not --script-args for security
                const safeScriptArgs = scriptArgs.filter(arg => 
                    arg.startsWith('--script') && !arg.startsWith('--script-args')
                );
                args = args.concat(safeScriptArgs);
            }
            
            // Add target (ensure it's validated)
            args.push(target);
            
            // Add verbose output for better real-time feedback
            if (!args.includes('-v')) {
                args.push('-v');
            }
            
            // Security: Limit scan to reasonable timeout
            if (!args.some(arg => arg.startsWith('--host-timeout'))) {
                args.push('--host-timeout', '300s'); // 5 minute max per host
            }
            
            // Add unprivileged flag for Windows compatibility
            if (process.platform === 'win32' && !args.includes('--unprivileged')) {
                args.unshift('--unprivileged');
            }
            
            console.log(`[NMAP] Executing: nmap ${args.join(' ')}`);
            console.log(`[NMAP] Target: ${target}`);
            console.log(`[NMAP] Platform: ${process.platform}`);
            
            const nmap = spawn('nmap', args, {
                stdio: ['pipe', 'pipe', 'pipe'],
                timeout: 600000, // 10 minute total timeout
                shell: process.platform === 'win32' // Use shell on Windows
            });
            
            let fullOutput = '';
            let hasReceivedData = false;
            
            // Handle stdout data (real-time output)
            nmap.stdout.on('data', (data) => {
                hasReceivedData = true;
                const output = data.toString();
                fullOutput += output;
                
                // Send real-time updates
                callback(null, {
                    type: 'stdout',
                    data: output,
                    isComplete: false
                });
            });
            
            // Handle stderr data (errors and warnings)
            nmap.stderr.on('data', (data) => {
                const output = data.toString();
                fullOutput += output;
                
                // Check for privilege errors and provide guidance
                if (output.toLowerCase().includes('requires root') || 
                    output.toLowerCase().includes('operation not permitted')) {
                    callback(null, {
                        type: 'stderr',
                        data: `${output}\n[INFO] Trying unprivileged scan method...`,
                        isComplete: false
                    });
                } else {
                    // Send error updates (but don't treat as fatal error)
                    callback(null, {
                        type: 'stderr',
                        data: output,
                        isComplete: false
                    });
                }
            });
            
            // Handle process completion
            nmap.on('close', (code) => {
                console.log(`Nmap process exited with code ${code}`);
                
                if (code === 0 || (hasReceivedData && fullOutput.length > 0)) {
                    callback(null, {
                        type: 'complete',
                        data: fullOutput || 'Scan completed successfully.',
                        isComplete: true,
                        exitCode: code
                    });
                } else if (code === 1 && fullOutput.toLowerCase().includes('requires root')) {
                    // Try fallback scan for privilege issues
                    this.executeFallbackScan(target, callback);
                } else {
                    callback(`Nmap exited with code ${code}`, {
                        type: 'error',
                        data: fullOutput || `Process exited with code ${code}`,
                        isComplete: true,
                        exitCode: code
                    });
                }
            });
            
            // Handle process errors
            nmap.on('error', (error) => {
                console.error(`Failed to start nmap: ${error.message}`);
                if (error.message.includes('ENOENT')) {
                    callback('Nmap not found. Please ensure Nmap is installed and in your PATH.', null);
                } else {
                    callback(`Failed to start nmap: ${error.message}`, null);
                }
            });

            return nmap; // Return the process object so it can be killed if needed
            
        } catch (err) {
            console.error(`Failed to run Nmap: ${err.message}`);
            callback(err.message, null);
        }
    }
    
    static convertToUnprivilegedScan(args) {
        // Convert privileged scan types to unprivileged alternatives
        const convertedArgs = [];
        
        for (let i = 0; i < args.length; i++) {
            let arg = args[i];
            
            // Convert SYN scan (-sS) to TCP Connect scan (-sT) for unprivileged
            if (arg === '-sS') {
                convertedArgs.push('-sT');
                console.log('[NMAP] Converting SYN scan (-sS) to TCP Connect scan (-sT) for unprivileged execution');
            }
            // Convert UDP scan (-sU) to TCP scan for unprivileged
            else if (arg === '-sU') {
                convertedArgs.push('-sT');
                console.log('[NMAP] Converting UDP scan (-sU) to TCP Connect scan (-sT) for unprivileged execution');
            }
            // Convert OS detection (-O) to version detection (-sV) for better compatibility
            else if (arg === '-O') {
                convertedArgs.push('-sV');
                console.log('[NMAP] Converting OS detection (-O) to version detection (-sV) for better compatibility');
            }
            // Keep other arguments as-is
            else {
                convertedArgs.push(arg);
            }
        }
        
        return convertedArgs;
    }
    
    static executeFallbackScan(target, callback) {
        console.log('[NMAP] Executing fallback unprivileged scan...');
        
        const fallbackArgs = [
            '--unprivileged',
            '-sT',  // TCP Connect scan (doesn't require root)
            '-T4',  // Aggressive timing
            '-v',   // Verbose
            '--host-timeout', '300s',
            target
        ];
        
        console.log(`[NMAP] Fallback scan: nmap ${fallbackArgs.join(' ')}`);
        
        const nmap = spawn('nmap', fallbackArgs, {
            stdio: ['pipe', 'pipe', 'pipe'],
            timeout: 600000,
            shell: process.platform === 'win32'
        });
        
        let fullOutput = 'FALLBACK UNPRIVILEGED SCAN:\n\n';
        
        nmap.stdout.on('data', (data) => {
            const output = data.toString();
            fullOutput += output;
            callback(null, {
                type: 'stdout',
                data: output,
                isComplete: false
            });
        });
        
        nmap.stderr.on('data', (data) => {
            const output = data.toString();
            fullOutput += output;
            callback(null, {
                type: 'stderr',
                data: output,
                isComplete: false
            });
        });
        
        nmap.on('close', (code) => {
            callback(null, {
                type: 'complete',
                data: fullOutput,
                isComplete: true,
                exitCode: code
            });
        });
        
        nmap.on('error', (error) => {
            callback(`Fallback scan failed: ${error.message}`, null);
        });
    }
    
    static validateTarget(target) {
        // Basic validation for IP addresses, domains, and URLs
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\.[a-zA-Z]{2,}$/;
        const urlRegex = /^https?:\/\/(www\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\.[a-zA-Z]{2,})/;
        
        if (ipRegex.test(target) || domainRegex.test(target)) {
            return true;
        }
        
        const urlMatch = target.match(urlRegex);
        if (urlMatch) {
            return true;
        }
        
        return false;
    }
    
    static processTarget(target) {
        // Extract domain from URL if it's a URL
        const urlRegex = /^https?:\/\/(www\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\.[a-zA-Z]{2,})/;
        const urlMatch = target.match(urlRegex);
        
        if (urlMatch) {
            // Return the domain part without www if present
            return urlMatch[2];
        }
        
        // Return target as-is if it's already an IP or domain
        return target;
    }
}

module.exports = NmapRunner;
