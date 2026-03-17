/**
 * Advanced File Monitoring System for Penetration Testing Tool
 * Monitors file operations (copy, move, modify, delete) with detailed logging
 * Integrates with IDS system for real-time security alerts
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const chokidar = require('chokidar'); // npm install chokidar

class FileMonitor {
    constructor() {
        this.watchers = new Map();
        this.fileHashes = new Map();
        this.alertCallbacks = [];
        this.config = {
            enableRealTimeMonitoring: true,
            monitoredExtensions: ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.sh', '.conf', '.cfg', '.ini', '.xml', '.json', '.log', '.key', '.cert', '.pem'],
            sensitiveDirectories: [
                '/etc',
                '/usr/bin',
                '/usr/sbin',
                '/bin',
                '/sbin',
                'C:\\Windows\\System32',
                'C:\\Program Files',
                'C:\\Users'
            ],
            excludeDirectories: [
                '/proc',
                '/sys',
                '/dev',
                'C:\\Windows\\Temp',
                path.join(os.tmpdir())
            ],
            maxFileSize: 100 * 1024 * 1024, // 100MB
            alertThresholds: {
                massOperations: 50, // Alert if more than 50 operations in 60 seconds
                timeWindow: 60000 // 60 seconds
            }
        };
        this.operationCounter = new Map();
        this.alertHistory = [];
    }

    /**
     * Initialize the file monitoring system
     */
    async initialize() {
        console.log('🔍 Initializing File Monitor System...');
        
        // Initialize baseline file hashes for critical files
        await this.initializeBaseline();
        
        // Start monitoring configured directories
        this.startMonitoring();
        
        console.log('✅ File Monitor System initialized successfully');
    }

    /**
     * Create baseline hashes for critical system files
     */
    async initializeBaseline() {
        const criticalFiles = this.getCriticalFiles();
        
        for (const filePath of criticalFiles) {
            try {
                if (fs.existsSync(filePath)) {
                    const hash = await this.calculateFileHash(filePath);
                    this.fileHashes.set(filePath, {
                        hash,
                        lastModified: fs.statSync(filePath).mtime,
                        size: fs.statSync(filePath).size
                    });
                }
            } catch (error) {
                console.warn(`Warning: Could not baseline file ${filePath}: ${error.message}`);
            }
        }
        
        console.log(`📊 Baselined ${this.fileHashes.size} critical files`);
    }

    /**
     * Get list of critical files to monitor
     */
    getCriticalFiles() {
        const isWindows = os.platform() === 'win32';
        
        if (isWindows) {
            return [
                'C:\\Windows\\System32\\notepad.exe',
                'C:\\Windows\\System32\\cmd.exe',
                'C:\\Windows\\System32\\powershell.exe',
                'C:\\Windows\\System32\\regedit.exe',
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                'C:\\Users\\Public\\Desktop'
            ];
        } else {
            return [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/sudoers',
                '/etc/hosts',
                '/bin/bash',
                '/bin/sh',
                '/usr/bin/sudo'
            ];
        }
    }

    /**
     * Start monitoring file system changes
     */
    startMonitoring() {
        const monitorPaths = this.config.sensitiveDirectories.filter(dir => {
            try {
                return fs.existsSync(dir) && !this.config.excludeDirectories.includes(dir);
            } catch {
                return false;
            }
        });

        monitorPaths.forEach(dirPath => {
            try {
                const watcher = chokidar.watch(dirPath, {
                    ignored: /(^|[\/\\])\../, // ignore dotfiles
                    persistent: true,
                    ignoreInitial: true,
                    depth: 3, // Limit recursion depth for performance
                    awaitWriteFinish: {
                        stabilityThreshold: 2000,
                        pollInterval: 100
                    }
                });

                watcher
                    .on('add', (filePath) => this.handleFileEvent('created', filePath))
                    .on('change', (filePath) => this.handleFileEvent('modified', filePath))
                    .on('unlink', (filePath) => this.handleFileEvent('deleted', filePath))
                    .on('addDir', (dirPath) => this.handleFileEvent('directory_created', dirPath))
                    .on('unlinkDir', (dirPath) => this.handleFileEvent('directory_deleted', dirPath))
                    .on('error', error => console.error(`File watcher error: ${error}`));

                this.watchers.set(dirPath, watcher);
                console.log(`📁 Monitoring: ${dirPath}`);
            } catch (error) {
                console.warn(`Warning: Could not monitor ${dirPath}: ${error.message}`);
            }
        });
    }

    /**
     * Handle file system events
     */
    async handleFileEvent(eventType, filePath) {
        try {
            const fileName = path.basename(filePath);
            const fileExt = path.extname(filePath).toLowerCase();
            const currentUser = os.userInfo().username;
            const timestamp = new Date().toISOString();
            
            // Skip if file extension is not monitored and not in sensitive directory
            if (this.config.monitoredExtensions.length > 0 && 
                !this.config.monitoredExtensions.includes(fileExt) &&
                !this.isInSensitiveDirectory(filePath)) {
                return;
            }

            // Get file stats if file still exists
            let fileStats = null;
            if (eventType !== 'deleted' && eventType !== 'directory_deleted') {
                try {
                    fileStats = fs.statSync(filePath);
                    if (fileStats.size > this.config.maxFileSize) {
                        console.log(`⚠️ Skipping large file: ${filePath} (${fileStats.size} bytes)`);
                        return;
                    }
                } catch (error) {
                    console.warn(`Could not get stats for ${filePath}: ${error.message}`);
                }
            }

            // Calculate file hash for integrity monitoring
            let fileHash = null;
            if (fileStats && fileStats.isFile() && (eventType === 'created' || eventType === 'modified')) {
                fileHash = await this.calculateFileHash(filePath);
            }

            // Create detailed alert object
            const alert = {
                id: crypto.randomUUID(),
                timestamp,
                eventType,
                filePath,
                fileName,
                fileExtension: fileExt,
                fileSize: fileStats ? fileStats.size : 0,
                fileHash,
                user: currentUser,
                processId: process.pid,
                severity: this.calculateSeverity(eventType, filePath, fileExt),
                isSuspicious: this.isSuspiciousActivity(eventType, filePath, fileExt),
                details: {
                    absolutePath: path.resolve(filePath),
                    directory: path.dirname(filePath),
                    isSystemFile: this.isSystemFile(filePath),
                    isSensitiveFile: this.isSensitiveFile(filePath),
                    integrityStatus: await this.checkIntegrity(filePath, fileHash)
                }
            };

            // Track operation frequency for mass operation detection
            this.trackOperationFrequency(currentUser, eventType);

            // Store alert in history
            this.alertHistory.push(alert);

            // Trigger callbacks
            this.triggerAlerts(alert);

            // Log to console
            this.logAlert(alert);

            // Update file hash baseline
            if (fileHash && fileStats) {
                this.fileHashes.set(filePath, {
                    hash: fileHash,
                    lastModified: fileStats.mtime,
                    size: fileStats.size
                });
            }

        } catch (error) {
            console.error(`Error handling file event: ${error.message}`);
        }
    }

    /**
     * Calculate file hash for integrity monitoring
     */
    async calculateFileHash(filePath) {
        return new Promise((resolve, reject) => {
            const hash = crypto.createHash('sha256');
            const stream = fs.createReadStream(filePath);
            
            stream.on('error', reject);
            stream.on('data', chunk => hash.update(chunk));
            stream.on('end', () => resolve(hash.digest('hex')));
        });
    }

    /**
     * Check file integrity against baseline
     */
    async checkIntegrity(filePath, currentHash) {
        if (!currentHash || !this.fileHashes.has(filePath)) {
            return 'unknown';
        }

        const baseline = this.fileHashes.get(filePath);
        return baseline.hash === currentHash ? 'intact' : 'modified';
    }

    /**
     * Calculate severity level for the event
     */
    calculateSeverity(eventType, filePath, fileExt) {
        let severity = 'low';

        // High severity events
        if (eventType === 'deleted' && this.isSystemFile(filePath)) {
            severity = 'critical';
        } else if (eventType === 'modified' && this.isSensitiveFile(filePath)) {
            severity = 'high';
        } else if (['.exe', '.dll', '.sys', '.bat', '.ps1', '.sh'].includes(fileExt)) {
            severity = 'high';
        } else if (eventType === 'created' && this.isInSensitiveDirectory(filePath)) {
            severity = 'medium';
        }

        return severity;
    }

    /**
     * Determine if activity is suspicious
     */
    isSuspiciousActivity(eventType, filePath, fileExt) {
        // Suspicious patterns
        const suspiciousPatterns = [
            /temp.*\.exe$/i,
            /.*\.tmp\.exe$/i,
            /.*\.(scr|pif|com|bat|cmd|ps1)$/i,
            /.*\.(key|cert|pem|crt)$/i,
            /shadow|passwd|sudoers/i
        ];

        return suspiciousPatterns.some(pattern => pattern.test(path.basename(filePath))) ||
               (eventType === 'deleted' && this.isSystemFile(filePath)) ||
               (eventType === 'created' && fileExt === '.exe' && this.isInSystemDirectory(filePath));
    }

    /**
     * Check if file is a system file
     */
    isSystemFile(filePath) {
        const systemPatterns = [
            /\/etc\//,
            /\/bin\//,
            /\/sbin\//,
            /\/usr\/bin\//,
            /\/usr\/sbin\//,
            /C:\\Windows\\System32/i,
            /C:\\Windows\\SysWOW64/i
        ];

        return systemPatterns.some(pattern => pattern.test(filePath));
    }

    /**
     * Check if file contains sensitive information
     */
    isSensitiveFile(filePath) {
        const sensitivePatterns = [
            /(password|secret|key|cert|private|credential|token)/i,
            /\.(key|cert|pem|crt|p12|pfx)$/i,
            /(shadow|passwd|sudoers|hosts\.allow|hosts\.deny)/i
        ];

        return sensitivePatterns.some(pattern => pattern.test(filePath));
    }

    /**
     * Check if path is in sensitive directory
     */
    isInSensitiveDirectory(filePath) {
        return this.config.sensitiveDirectories.some(sensitiveDir => 
            filePath.toLowerCase().startsWith(sensitiveDir.toLowerCase())
        );
    }

    /**
     * Check if path is in system directory
     */
    isInSystemDirectory(filePath) {
        const systemDirs = [
            '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/etc',
            'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64', 'C:\\Program Files'
        ];

        return systemDirs.some(sysDir => 
            filePath.toLowerCase().startsWith(sysDir.toLowerCase())
        );
    }

    /**
     * Track operation frequency for mass operation detection
     */
    trackOperationFrequency(user, eventType) {
        const key = `${user}:${eventType}`;
        const now = Date.now();
        
        if (!this.operationCounter.has(key)) {
            this.operationCounter.set(key, []);
        }
        
        const operations = this.operationCounter.get(key);
        operations.push(now);
        
        // Remove old operations outside time window
        const cutoff = now - this.config.alertThresholds.timeWindow;
        const recentOps = operations.filter(timestamp => timestamp > cutoff);
        this.operationCounter.set(key, recentOps);
        
        // Check for mass operations
        if (recentOps.length >= this.config.alertThresholds.massOperations) {
            this.triggerMassOperationAlert(user, eventType, recentOps.length);
        }
    }

    /**
     * Trigger mass operation alert
     */
    triggerMassOperationAlert(user, eventType, count) {
        const alert = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            eventType: 'mass_operations',
            severity: 'high',
            user,
            operationType: eventType,
            operationCount: count,
            timeWindow: this.config.alertThresholds.timeWindow / 1000,
            isSuspicious: true,
            details: {
                description: `User ${user} performed ${count} ${eventType} operations in ${this.config.alertThresholds.timeWindow / 1000} seconds`,
                potentialThreat: 'Mass file operations could indicate malware activity, data exfiltration, or system compromise'
            }
        };

        this.triggerAlerts(alert);
        this.logAlert(alert);
    }

    /**
     * Register alert callback
     */
    onAlert(callback) {
        this.alertCallbacks.push(callback);
    }

    /**
     * Trigger all registered alert callbacks
     */
    triggerAlerts(alert) {
        this.alertCallbacks.forEach(callback => {
            try {
                callback(alert);
            } catch (error) {
                console.error(`Alert callback error: ${error.message}`);
            }
        });
    }

    /**
     * Log alert to console
     */
    logAlert(alert) {
        const icon = this.getSeverityIcon(alert.severity);
        const suspiciousFlag = alert.isSuspicious ? ' 🚨 SUSPICIOUS' : '';
        
        console.log(`${icon} [FILE MONITOR] ${alert.eventType.toUpperCase()}${suspiciousFlag}`);
        console.log(`   📂 File: ${alert.filePath}`);
        console.log(`   👤 User: ${alert.user}`);
        console.log(`   ⏰ Time: ${alert.timestamp}`);
        console.log(`   🔒 Severity: ${alert.severity.toUpperCase()}`);
        
        if (alert.details) {
            if (alert.details.integrityStatus === 'modified') {
                console.log(`   ⚠️  Integrity: File hash changed - possible tampering detected`);
            }
            if (alert.details.isSystemFile) {
                console.log(`   🛡️  System File: Critical system file affected`);
            }
            if (alert.details.isSensitiveFile) {
                console.log(`   🔐 Sensitive File: Contains sensitive information`);
            }
        }
        console.log('');
    }

    /**
     * Get icon for severity level
     */
    getSeverityIcon(severity) {
        const icons = {
            critical: '🔴',
            high: '🟠',
            medium: '🟡',
            low: '🔵'
        };
        return icons[severity] || '⚪';
    }

    /**
     * Generate file monitoring report
     */
    generateReport(timeRange = 24) { // Default 24 hours
        const cutoff = new Date(Date.now() - (timeRange * 60 * 60 * 1000));
        const recentAlerts = this.alertHistory.filter(alert => new Date(alert.timestamp) > cutoff);
        
        const report = {
            reportId: crypto.randomUUID(),
            generatedAt: new Date().toISOString(),
            timeRange: `${timeRange} hours`,
            summary: {
                totalAlerts: recentAlerts.length,
                criticalAlerts: recentAlerts.filter(a => a.severity === 'critical').length,
                highAlerts: recentAlerts.filter(a => a.severity === 'high').length,
                suspiciousActivities: recentAlerts.filter(a => a.isSuspicious).length,
                uniqueUsers: [...new Set(recentAlerts.map(a => a.user))].length,
                mostActiveUser: this.getMostActiveUser(recentAlerts),
                topFileTypes: this.getTopFileTypes(recentAlerts)
            },
            alerts: recentAlerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)),
            integrityViolations: recentAlerts.filter(a => a.details && a.details.integrityStatus === 'modified'),
            recommendations: this.generateRecommendations(recentAlerts)
        };

        return report;
    }

    /**
     * Get most active user from alerts
     */
    getMostActiveUser(alerts) {
        const userCounts = {};
        alerts.forEach(alert => {
            userCounts[alert.user] = (userCounts[alert.user] || 0) + 1;
        });
        
        return Object.keys(userCounts).reduce((a, b) => 
            userCounts[a] > userCounts[b] ? a : b, null
        );
    }

    /**
     * Get top file types from alerts
     */
    getTopFileTypes(alerts) {
        const typeCounts = {};
        alerts.forEach(alert => {
            if (alert.fileExtension) {
                typeCounts[alert.fileExtension] = (typeCounts[alert.fileExtension] || 0) + 1;
            }
        });
        
        return Object.entries(typeCounts)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5)
            .map(([ext, count]) => ({ extension: ext, count }));
    }

    /**
     * Generate security recommendations based on alerts
     */
    generateRecommendations(alerts) {
        const recommendations = [];
        
        const criticalAlerts = alerts.filter(a => a.severity === 'critical');
        if (criticalAlerts.length > 0) {
            recommendations.push({
                priority: 'high',
                category: 'critical_files',
                message: `${criticalAlerts.length} critical file operations detected. Immediately investigate system file modifications.`
            });
        }
        
        const integrityViolations = alerts.filter(a => a.details && a.details.integrityStatus === 'modified');
        if (integrityViolations.length > 0) {
            recommendations.push({
                priority: 'high',
                category: 'integrity',
                message: `${integrityViolations.length} file integrity violations detected. Verify file authenticity and scan for malware.`
            });
        }
        
        const suspiciousFiles = alerts.filter(a => a.isSuspicious);
        if (suspiciousFiles.length > 5) {
            recommendations.push({
                priority: 'medium',
                category: 'suspicious_activity',
                message: `High volume of suspicious file activities (${suspiciousFiles.length}). Consider implementing stricter access controls.`
            });
        }
        
        return recommendations;
    }

    /**
     * Stop monitoring
     */
    stopMonitoring() {
        this.watchers.forEach(watcher => {
            watcher.close();
        });
        this.watchers.clear();
        console.log('🛑 File monitoring stopped');
    }

    /**
     * Get current monitoring status
     */
    getStatus() {
        return {
            isActive: this.watchers.size > 0,
            monitoredDirectories: Array.from(this.watchers.keys()),
            totalAlerts: this.alertHistory.length,
            recentAlerts: this.alertHistory.slice(-10),
            baselinedFiles: this.fileHashes.size
        };
    }
}

module.exports = FileMonitor;
