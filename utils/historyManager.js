const fs = require('fs').promises;
const path = require('path');
const storagePaths = require('./storagePaths');

class HistoryManager {
    constructor() {
        this.dataDir = storagePaths.getDataDir();
        this.historyFile = path.join(this.dataDir, 'history.json');
        this.ensureDataDir();
    }

    async ensureDataDir() {
        try {
            await fs.access(this.dataDir);
        } catch {
            await fs.mkdir(this.dataDir, { recursive: true });
        }
    }

    async loadHistory() {
        try {
            const data = await fs.readFile(this.historyFile, 'utf8');
            return JSON.parse(data);
        } catch {
            // Return default structure if file doesn't exist
            return {
                scans: [],
                reports: [],
                statistics: {
                    totalScans: 0,
                    successfulScans: 0,
                    failedScans: 0,
                    totalReports: 0,
                    uniqueTargets: []
                }
            };
        }
    }

    async saveHistory(history) {
        try {
            await this.ensureDataDir();
            await fs.writeFile(this.historyFile, JSON.stringify(history, null, 2), 'utf8');
        } catch (error) {
            console.error('Error saving history:', error);
        }
    }

    generateScanId() {
        return `SCAN_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    }

    async addScan(scanData) {
        try {
            const history = await this.loadHistory();
            
            const scanEntry = {
                id: this.generateScanId(),
                target: scanData.target,
                scanType: scanData.scanType || scanData.command,
                status: scanData.status || 'In Progress',
                startTime: scanData.startTime || new Date().toISOString(),
                endTime: scanData.endTime,
                duration: scanData.duration,
                pentester: scanData.pentester || 'Security Analyst',
                outputSize: scanData.output ? scanData.output.length : 0,
                hostsFound: this.parseHostsFound(scanData.output),
                portsFound: this.parsePortsFound(scanData.output),
                reportGenerated: scanData.reportGenerated || false,
                reportId: scanData.reportId,
                timestamp: new Date().toISOString()
            };

            history.scans.unshift(scanEntry); // Add to beginning for newest first
            
            // Update statistics
            history.statistics.totalScans++;
            if (scanData.status === 'Completed') {
                history.statistics.successfulScans++;
            } else if (scanData.status === 'Failed') {
                history.statistics.failedScans++;
            }

            // Track unique targets
            if (!history.statistics.uniqueTargets.includes(scanData.target)) {
                history.statistics.uniqueTargets.push(scanData.target);
            }

            // Keep only last 100 scans to prevent file from growing too large
            if (history.scans.length > 100) {
                history.scans = history.scans.slice(0, 100);
            }

            await this.saveHistory(history);
            return scanEntry;
        } catch (error) {
            console.error('Error adding scan to history:', error);
            return null;
        }
    }

    async addReport(reportData) {
        try {
            const history = await this.loadHistory();
            
            const reportEntry = {
                id: reportData.reportId || `RPT_${Date.now()}`,
                scanId: reportData.scanId,
                filename: reportData.filename,
                target: reportData.target,
                format: reportData.format || 'HTML',
                size: reportData.size,
                created: new Date().toISOString(),
                pentester: reportData.pentester || 'Security Analyst',
                filepath: reportData.filepath,
                scanType: reportData.scanType || 'Network Scan'
            };

            history.reports.unshift(reportEntry);
            history.statistics.totalReports++;

            // Keep only last 50 reports
            if (history.reports.length > 50) {
                history.reports = history.reports.slice(0, 50);
            }

            await this.saveHistory(history);
            return reportEntry;
        } catch (error) {
            console.error('Error adding report to history:', error);
            return null;
        }
    }

    async updateScanStatus(scanId, status, endTime = null, output = null) {
        try {
            const history = await this.loadHistory();
            const scanIndex = history.scans.findIndex(scan => scan.id === scanId);
            
            if (scanIndex !== -1) {
                history.scans[scanIndex].status = status;
                if (endTime) {
                    history.scans[scanIndex].endTime = endTime;
                    
                    // Calculate duration
                    const start = new Date(history.scans[scanIndex].startTime);
                    const end = new Date(endTime);
                    const duration = Math.round((end - start) / 1000); // in seconds
                    history.scans[scanIndex].duration = `${duration}s`;
                }
                
                if (output) {
                    history.scans[scanIndex].outputSize = output.length;
                    history.scans[scanIndex].hostsFound = this.parseHostsFound(output);
                    history.scans[scanIndex].portsFound = this.parsePortsFound(output);
                    history.scans[scanIndex].analysis = this.generateAnalysis(output);
                }

                await this.saveHistory(history);
                return history.scans[scanIndex];
            }
        } catch (error) {
            console.error('Error updating scan status:', error);
        }
        return null;
    }

    generateAnalysis(output) {
        if (!output) return null;

        const services = [];
        const vulnerabilities = [];
        let hostsFound = 0;
        let portsOpen = 0;

        const lines = output.split('\n');
        let inPortSection = false;

        for (const line of lines) {
            const cleanLine = line.trim();

            if (cleanLine.includes('host(s) up')) {
                const hostMatch = cleanLine.match(/(\d+)\s+host/);
                if (hostMatch) hostsFound = parseInt(hostMatch[1]);
            }

            if (cleanLine.match(/^PORT|^PORT\s+STATE/) || (cleanLine.includes('PORT') && cleanLine.includes('STATE'))) {
                inPortSection = true;
                continue;
            }

            if (inPortSection && cleanLine.match(/^\d+\/\w+\s+\w+/)) {
                const parts = cleanLine.split(/\s+/);
                if (parts.length >= 3) {
                    const portProto = parts[0];
                    const state = parts[1];
                    const serviceInfo = parts.slice(2).join(' ');

                    const portMatch = portProto.match(/^(\d+)\/(\w+)$/);
                    if (portMatch) {
                        const port = portMatch[1];
                        const protocol = portMatch[2];

                        let service = 'unknown';
                        let version = '';

                        if (serviceInfo.includes('(')) {
                            const versionMatch = serviceInfo.match(/^([^\(]+)\(([^)]+)\)/);
                            if (versionMatch) {
                                service = versionMatch[1].trim();
                                version = versionMatch[2].trim();
                            }
                        } else {
                            const serviceParts = serviceInfo.split(/\s+/);
                            service = serviceParts[0] || 'unknown';
                            version = serviceParts.slice(1).join(' ') || serviceInfo;
                        }

                        if (state === 'open') {
                            portsOpen++;
                            services.push({
                                port: port,
                                protocol: protocol,
                                state: state,
                                service: service,
                                version: version || serviceInfo
                            });

                            const svcLower = service.toLowerCase();
                            const vulnServices = ['telnet', 'ftp', 'http', 'smtp', 'dns', 'msrpc', 'netbios-ssn', 'smb', 'rdp', 'ssh', 'mysql', 'mongodb', 'redis', 'vnc', 'postgresql', 'mongodb', 'redis'];
                            if (vulnServices.some(s => svcLower.includes(s))) {
                                vulnerabilities.push(`${service} (Port ${port})`);
                            }
                        }
                    }
                }
            }

            if (inPortSection && cleanLine === '' && services.length > 0) {
                inPortSection = false;
            }
        }

        return {
            services: services,
            vulnerabilities: vulnerabilities,
            hostsFound: hostsFound,
            portsOpen: portsOpen,
            summary: this.generateSummary(services, vulnerabilities, hostsFound)
        };
    }

    generateSummary(services, vulnerabilities, hostsFound = 0) {
        const serviceCount = services.length;
        const vulnCount = vulnerabilities.length;

        let summary = `Found ${serviceCount} open ports`;
        if (hostsFound > 0) summary += ` on ${hostsFound} host(s)`;
        summary += '.';
        if (vulnCount > 0) {
            summary += ` ${vulnCount} security considerations detected.`;
            const highRisk = vulnerabilities.filter(v => ['smb', 'rdp', 'telnet', 'redis'].some(s => v.toLowerCase().includes(s))).length;
            const mediumRisk = vulnerabilities.filter(v => ['ssh', 'ftp', 'http', 'smtp', 'dns', 'msrpc', 'netbios'].some(s => v.toLowerCase().includes(s))).length;
            if (highRisk > 0) summary += ` ${highRisk} high-risk services (SMB, RDP, Telnet, Redis).`;
            if (mediumRisk > 0) summary += ` ${mediumRisk} medium-risk services.`;
        }

        return summary;
    }

    parseHostsFound(output) {
        if (!output) return 0;
        const match = output.match(/(\d+) host[s]? up/);
        return match ? parseInt(match[1]) : 0;
    }

    parsePortsFound(output) {
        if (!output) return 0;
        const matches = output.match(/\d+\/\w+\s+open/g);
        return matches ? matches.length : 0;
    }

    async getHistory() {
        return await this.loadHistory();
    }

    async getRecentScans(limit = 10) {
        const history = await this.loadHistory();
        return history.scans.slice(0, limit);
    }

    async getRecentReports(limit = 10) {
        const history = await this.loadHistory();
        return history.reports.slice(0, limit);
    }

    async getStatistics() {
        const history = await this.loadHistory();
        return history.statistics;
    }

    async getScanById(scanId) {
        const history = await this.loadHistory();
        return history.scans.find(scan => scan.id === scanId);
    }

    async getReportById(reportId) {
        const history = await this.loadHistory();
        return history.reports.find(report => report.id === reportId);
    }

    async deleteScan(scanId) {
        try {
            const history = await this.loadHistory();
            const index = history.scans.findIndex(scan => scan.id === scanId);
            
            if (index !== -1) {
                const deletedScan = history.scans.splice(index, 1)[0];
                history.statistics.totalScans = Math.max(0, history.statistics.totalScans - 1);
                
                if (deletedScan.status === 'Completed') {
                    history.statistics.successfulScans = Math.max(0, history.statistics.successfulScans - 1);
                } else if (deletedScan.status === 'Failed') {
                    history.statistics.failedScans = Math.max(0, history.statistics.failedScans - 1);
                }

                await this.saveHistory(history);
                return true;
            }
        } catch (error) {
            console.error('Error deleting scan:', error);
        }
        return false;
    }

    async deleteReport(reportId) {
        try {
            const history = await this.loadHistory();
            const index = history.reports.findIndex(report => report.id === reportId);
            
            if (index !== -1) {
                history.reports.splice(index, 1);
                history.statistics.totalReports = Math.max(0, history.statistics.totalReports - 1);
                await this.saveHistory(history);
                return true;
            }
        } catch (error) {
            console.error('Error deleting report:', error);
        }
        return false;
    }

    async clearHistory() {
        try {
            const emptyHistory = {
                scans: [],
                reports: [],
                statistics: {
                    totalScans: 0,
                    successfulScans: 0,
                    failedScans: 0,
                    totalReports: 0,
                    uniqueTargets: []
                }
            };
            await this.saveHistory(emptyHistory);
            return true;
        } catch (error) {
            console.error('Error clearing history:', error);
            return false;
        }
    }
}

module.exports = HistoryManager;
