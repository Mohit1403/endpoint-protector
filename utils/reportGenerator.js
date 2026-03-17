const fs = require('fs').promises;
const path = require('path');
const jsPDF = require('jspdf').jsPDF;
const storagePaths = require('./storagePaths');

class ReportGenerator {
    constructor() {
        this.reportsDir = storagePaths.getReportsDir();
        this.ensureReportsDir();
    }

    async ensureReportsDir() {
        try {
            await fs.access(this.reportsDir);
        } catch {
            await fs.mkdir(this.reportsDir, { recursive: true });
        }
    }

    generateReportId() {
        return `PENTEST_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    generateProfessionalFilename(scanData, format) {
        try {
            // Clean and format target name
            const targetName = this.sanitizeFilename(scanData.target);
            
            // Format date as YYYY-MM-DD
            const date = new Date(scanData.startTime || new Date());
            const dateStr = date.toISOString().split('T')[0]; // YYYY-MM-DD
            
            // Clean scan type
            const scanType = this.sanitizeFilename(scanData.scanType || 'NetworkScan');
            
            // Clean pentester name
            const pentesterName = this.sanitizeFilename(scanData.pentester || 'SecurityAnalyst');
            
            // Determine report type based on scan data
            let reportType = 'PenetrationTest';
            if (scanData.scanType) {
                if (scanData.scanType.toLowerCase().includes('virustotal')) {
                    reportType = 'MalwareAnalysis';
                } else if (scanData.scanType.toLowerCase().includes('ids')) {
                    reportType = 'ThreatIntelligence';
                } else if (scanData.scanType.toLowerCase().includes('iot') || scanData.scanType.toLowerCase().includes('ics')) {
                    reportType = 'IoT-ICS-Security';
                } else if (scanData.scanType.toLowerCase().includes('crypto')) {
                    reportType = 'CryptographyAnalysis';
                }
            }
            
            // Generate time component for uniqueness (HHMM)
            const timeStr = date.toTimeString().substr(0, 5).replace(':', '');
            
            // Build filename: ReportType_Target_Date_Time_Analyst.format
            const filename = `${reportType}_${targetName}_${dateStr}_${timeStr}_${pentesterName}.${format}`;
            
            return filename;
        } catch (error) {
            console.warn('Error generating professional filename:', error);
            // Fallback to timestamp-based naming
            const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
            return `SecurityReport_${timestamp}.${format}`;
        }
    }
    
    sanitizeFilename(input) {
        if (!input || typeof input !== 'string') return 'Unknown';
        
        return input
            .replace(/[^a-zA-Z0-9\-_.]/g, '_') // Replace invalid chars with underscore
            .replace(/_{2,}/g, '_') // Replace multiple underscores with single
            .replace(/^_+|_+$/g, '') // Remove leading/trailing underscores
            .substr(0, 50) // Limit length
            || 'Unknown';
    }

    formatTimestamp(date = new Date()) {
        // Sync with local machine timezone
        const localDate = new Date(date.toLocaleString());
        return localDate.toLocaleString('en-US', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            timeZoneName: 'short'
        });
    }

    parseNmapOutput(nmapOutput) {
        try {
            const analysis = {
                hostsFound: 0,
                portsOpen: 0,
                services: [],
                vulnerabilities: [],
                summary: ''
            };

            // Handle null or undefined output
            if (!nmapOutput || typeof nmapOutput !== 'string') {
                console.warn('Invalid nmap output provided to parseNmapOutput');
                analysis.summary = 'No valid scan output available for analysis.';
                return analysis;
            }

            const lines = nmapOutput.split('\n');
            
            // Parse basic statistics with multiple patterns
            const hostUpPatterns = [
                /(\d+) host[s]? up/,
                /Nmap scan report for .+/g,
                /Host is up/
            ];
            
            // Try different patterns to find hosts
            for (const pattern of hostUpPatterns) {
                const match = nmapOutput.match(pattern);
                if (match) {
                    if (pattern === hostUpPatterns[0]) {
                        analysis.hostsFound = parseInt(match[1]);
                        break;
                    } else if (pattern === hostUpPatterns[1]) {
                        const matches = nmapOutput.match(pattern);
                        analysis.hostsFound = matches ? matches.length : 0;
                        break;
                    } else if (pattern === hostUpPatterns[2]) {
                        analysis.hostsFound = 1;
                        break;
                    }
                }
            }

            // Parse open ports with enhanced pattern matching
            const portPatterns = [
                /(\d+\/\w+)\s+open\s+([\w-]+)/g,
                /(\d+\/\w+)\s+(open)\s+([\w-]+)/g,
                /PORT\s+STATE\s+SERVICE/
            ];
            
            let openPortMatches = [];
            for (const pattern of portPatterns.slice(0, 2)) {
                const matches = Array.from(nmapOutput.matchAll(pattern));
                if (matches.length > 0) {
                    openPortMatches = matches;
                    break;
                }
            }
            
            analysis.portsOpen = openPortMatches.length;
            
            openPortMatches.forEach(match => {
                try {
                    const port = match[1];
                    const service = match[2] === 'open' ? match[3] : match[2];
                    if (port && service) {
                        analysis.services.push({ port, service });
                    }
                } catch (parseError) {
                    console.warn('Error parsing port match:', parseError);
                }
            });

            // Detect potential security issues with more comprehensive checks
            const securityChecks = [
                { pattern: /22\/tcp\s+open\s+(ssh|SSH)/, message: 'SSH service detected - Ensure strong authentication' },
                { pattern: /80\/tcp\s+open\s+(http|HTTP)/, message: 'HTTP service detected - Consider HTTPS encryption' },
                { pattern: /443\/tcp\s+open\s+(https|HTTPS)/, message: 'HTTPS service detected - Verify SSL/TLS configuration' },
                { pattern: /21\/tcp\s+open\s+(ftp|FTP)/, message: 'FTP service detected - Known security risks' },
                { pattern: /23\/tcp\s+open\s+(telnet|TELNET)/, message: 'Telnet service detected - Unencrypted protocol' },
                { pattern: /25\/tcp\s+open\s+(smtp|SMTP)/, message: 'SMTP service detected - Review mail server security' },
                { pattern: /53\/tcp\s+open\s+(domain|DNS)/, message: 'DNS service detected - Verify DNS security settings' },
                { pattern: /135\/tcp\s+open\s+(msrpc|RPC)/, message: 'Microsoft RPC detected - Review RPC security' },
                { pattern: /139\/tcp\s+open\s+(netbios|NetBIOS)/, message: 'NetBIOS service detected - Consider disabling if not needed' },
                { pattern: /445\/tcp\s+open\s+(microsoft-ds|SMB)/, message: 'SMB service detected - Ensure proper authentication' },
                { pattern: /3389\/tcp\s+open\s+(ms-wbt-server|RDP)/, message: 'RDP service detected - Ensure strong passwords and NLA' }
            ];
            
            securityChecks.forEach(check => {
                if (check.pattern.test(nmapOutput)) {
                    analysis.vulnerabilities.push(check.message);
                }
            });

            // Generate summary
            analysis.summary = this.generateSummary(analysis);

            return analysis;
        } catch (error) {
            console.error('Error parsing nmap output:', error);
            return {
                hostsFound: 0,
                portsOpen: 0,
                services: [],
                vulnerabilities: ['Error parsing scan results'],
                summary: 'An error occurred while analyzing the scan results. Raw output is available below.'
            };
        }
    }

    generateSummary(analysis) {
        let summary = `Target assessment completed. `;
        
        if (analysis.hostsFound > 0) {
            summary += `${analysis.hostsFound} host(s) were found to be active. `;
        }
        
        if (analysis.portsOpen > 0) {
            summary += `${analysis.portsOpen} open port(s) were discovered, `;
            summary += `running services including: ${analysis.services.map(s => s.service).join(', ')}. `;
        } else {
            summary += `No open ports were discovered. `;
        }
        
        if (analysis.vulnerabilities.length > 0) {
            summary += `${analysis.vulnerabilities.length} potential security consideration(s) identified.`;
        } else {
            summary += `No immediate security concerns identified.`;
        }

        return summary;
    }
    
    async generatePDFReport(scanData) {
        try {
            // Validate input data
            if (!scanData) {
                throw new Error('Scan data is required for PDF generation');
            }

            // Ensure required fields have default values
            const safeData = {
                target: scanData.target || 'Unknown Target',
                pentester: scanData.pentester || 'Security Analyst',
                startTime: scanData.startTime || new Date().toISOString(),
                duration: scanData.duration || 'N/A',
                scanType: scanData.scanType || 'Network Scan',
                status: scanData.status || 'Completed',
                output: scanData.output || 'No scan output available'
            };

            const analysis = this.parseNmapOutput(safeData.output);
            const reportId = this.generateReportId();
            
            const doc = new jsPDF();
            const pageWidth = doc.internal.pageSize.getWidth();
            const margin = 20;
            let currentY = 20;
            
            // Helper function to add text with word wrapping and error handling
            const addText = (text, x, y, maxWidth = pageWidth - 2 * margin, fontSize = 12, fontStyle = 'normal') => {
                try {
                    doc.setFontSize(fontSize);
                    doc.setFont(undefined, fontStyle);
                    const safeText = String(text || '').replace(/[^\x00-\x7F]/g, '?'); // Replace non-ASCII chars
                    const splitText = doc.splitTextToSize(safeText, maxWidth);
                    doc.text(splitText, x, y);
                    return y + (splitText.length * (fontSize * 0.4));
                } catch (textError) {
                    console.warn('Error adding text to PDF:', textError);
                    return y + fontSize;
                }
            };
            
            // Add header with professional styling
            try {
                doc.setFillColor(41, 98, 255);
                doc.rect(0, 0, pageWidth, 40, 'F');
                doc.setTextColor(255, 255, 255);
                doc.setFontSize(24);
                doc.setFont(undefined, 'bold');
                doc.text('PENETRATION TESTING REPORT', pageWidth / 2, 25, { align: 'center' });
            } catch (headerError) {
                console.warn('Error adding header to PDF:', headerError);
                doc.setTextColor(0, 0, 0);
                doc.setFontSize(18);
                doc.text('PENETRATION TESTING REPORT', margin, 25);
            }
            
            currentY = 60;
            doc.setTextColor(0, 0, 0);
            doc.setFont(undefined, 'normal');
            
            // Report metadata
            try {
                doc.setFillColor(240, 240, 240);
                doc.rect(margin, currentY - 10, pageWidth - 2 * margin, 80, 'F');
            } catch (bgError) {
                console.warn('Error adding background to PDF:', bgError);
            }
            
            currentY = addText('REPORT INFORMATION', margin + 10, currentY + 5, undefined, 14, 'bold');
            
            currentY = addText(`Report ID: ${reportId}`, margin + 10, currentY + 5) + 3;
            currentY = addText(`Pentester: ${safeData.pentester}`, margin + 10, currentY) + 3;
            currentY = addText(`Target: ${safeData.target}`, margin + 10, currentY) + 3;
            
            try {
                const scanDate = this.formatTimestamp(new Date(safeData.startTime));
                currentY = addText(`Scan Date: ${scanDate}`, margin + 10, currentY) + 3;
            } catch (dateError) {
                console.warn('Error formatting date:', dateError);
                currentY = addText(`Scan Date: ${safeData.startTime}`, margin + 10, currentY) + 3;
            }
            
            currentY = addText(`Duration: ${safeData.duration}`, margin + 10, currentY) + 3;
            currentY = addText(`Scan Type: ${safeData.scanType}`, margin + 10, currentY) + 3;
            currentY = addText(`Status: ${safeData.status}`, margin + 10, currentY) + 15;
            
            // Executive Summary
            currentY = addText('EXECUTIVE SUMMARY', margin, currentY, undefined, 16, 'bold') + 5;
            currentY = addText(analysis.summary, margin, currentY, undefined, 11) + 15;
            
            // Statistics section
            currentY = addText('SCAN STATISTICS', margin, currentY, undefined, 16, 'bold') + 5;
            
            const stats = [
                `Hosts Found: ${analysis.hostsFound}`,
                `Open Ports: ${analysis.portsOpen}`,
                `Services Detected: ${analysis.services.length}`,
                `Security Considerations: ${analysis.vulnerabilities.length}`
            ];
            
            stats.forEach(stat => {
                currentY = addText(`• ${stat}`, margin + 10, currentY, undefined, 11) + 3;
            });
            currentY += 10;
            
            // Services section (if any)
            if (analysis.services.length > 0) {
                currentY = addText('DISCOVERED SERVICES', margin, currentY, undefined, 16, 'bold') + 10;
                analysis.services.forEach(service => {
                    if (currentY > 260) { 
                        doc.addPage(); 
                        currentY = 20; 
                        currentY = addText('DISCOVERED SERVICES (CONTINUED)', margin, currentY, undefined, 16, 'bold') + 10;
                    }
                    const serviceText = `• Port ${service.port}: ${service.service} (Open)`;
                    currentY = addText(serviceText, margin + 10, currentY, undefined, 11) + 3;
                });
                currentY += 10;
            }
            
            // Security considerations (if any)
            if (analysis.vulnerabilities.length > 0) {
                if (currentY > 200) { doc.addPage(); currentY = 20; }
                currentY = addText('SECURITY CONSIDERATIONS', margin, currentY, undefined, 16, 'bold') + 10;
                analysis.vulnerabilities.forEach((vuln, index) => {
                    if (currentY > 260) { 
                        doc.addPage(); 
                        currentY = 20; 
                        currentY = addText('SECURITY CONSIDERATIONS (CONTINUED)', margin, currentY, undefined, 16, 'bold') + 10;
                    }
                    currentY = addText(`${index + 1}. ${vuln}`, margin + 10, currentY, undefined, 11) + 5;
                });
                currentY += 10;
            }
            
            // Raw scan output section
            if (currentY > 200) { doc.addPage(); currentY = 20; }
            currentY = addText('RAW SCAN OUTPUT', margin, currentY, undefined, 16, 'bold') + 10;
            
            try {
                doc.setFont('courier', 'normal');
            } catch (fontError) {
                console.warn('Error setting courier font, using default:', fontError);
                doc.setFont(undefined, 'normal');
            }
            
            const output = safeData.output;
            const outputLines = output.split('\n');
            
            // Limit output lines to prevent memory issues
            const maxLines = 500;
            const linesToProcess = outputLines.slice(0, maxLines);
            if (outputLines.length > maxLines) {
                linesToProcess.push('...', `[Output truncated - ${outputLines.length - maxLines} additional lines not shown]`);
            }
            
            linesToProcess.forEach((line, index) => {
                if (currentY > 270) {
                    doc.addPage();
                    currentY = 20;
                    currentY = addText('RAW SCAN OUTPUT (CONTINUED)', margin, currentY, undefined, 16, 'bold') + 10;
                }
                // Clean the line to avoid PDF generation issues
                const cleanLine = String(line).replace(/[^\x00-\x7F]/g, '?').substring(0, 100);
                currentY = addText(cleanLine, margin, currentY, undefined, 8) + 2;
            });
            
            // Footer
            try {
                const pageCount = doc.internal.getNumberOfPages();
                for (let i = 1; i <= pageCount; i++) {
                    doc.setPage(i);
                    doc.setFontSize(8);
                    doc.setFont(undefined, 'normal');
                    doc.setTextColor(128, 128, 128);
                    const footerText1 = `Generated by Automated Penetration Testing Tool - Page ${i} of ${pageCount}`;
                    const footerText2 = `Report generated on ${this.formatTimestamp()}`;
                    doc.text(footerText1, pageWidth / 2, 285, { align: 'center' });
                    doc.text(footerText2, pageWidth / 2, 290, { align: 'center' });
                }
            } catch (footerError) {
                console.warn('Error adding footer to PDF:', footerError);
            }
            
            return doc.output('arraybuffer');
        } catch(error) {
            console.error("PDF Generation Failed:", error);
            console.error('Scan data that caused error:', JSON.stringify(scanData, null, 2));
            throw new Error(`Failed to generate PDF report: ${error.message}`);
        }
    }

    generateHTMLReport(scanData) {
        const analysis = this.parseNmapOutput(scanData.output);
        const reportId = this.generateReportId();
        
        return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Testing Report - ${reportId}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .report-container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #667eea;
            padding-bottom: 30px;
            margin-bottom: 40px;
        }
        .header h1 {
            color: #2c3e50;
            font-size: 2.5em;
            margin: 0;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
        }
        .header .subtitle {
            color: #7f8c8d;
            font-size: 1.2em;
            margin-top: 10px;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .info-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            border-left: 5px solid #667eea;
        }
        .info-card h3 {
            margin: 0 0 10px 0;
            color: #2c3e50;
            font-size: 1.1em;
        }
        .info-card p {
            margin: 0;
            color: #555;
            font-weight: bold;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #2c3e50;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        .services-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .services-table th {
            background: #2c3e50;
            color: white;
            padding: 15px;
            text-align: left;
        }
        .services-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #ecf0f1;
        }
        .services-table tr:hover {
            background: #f8f9fa;
        }
        .vulnerability {
            background: #fff5f5;
            border: 1px solid #fed7d7;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
        }
        .vulnerability h4 {
            color: #c53030;
            margin: 0 0 10px 0;
        }
        .vulnerability p {
            margin: 0;
            color: #2d3748;
        }
        .command-output {
            background: #1a202c;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        .footer {
            text-align: center;
            margin-top: 50px;
            padding-top: 30px;
            border-top: 2px solid #ecf0f1;
            color: #7f8c8d;
        }
        .severity-high { border-left-color: #e53e3e; }
        .severity-medium { border-left-color: #dd6b20; }
        .severity-low { border-left-color: #38a169; }
    </style>
</head>
<body>
    <div class="report-container">
        <div class="header">
            <h1>🛡️ Penetration Testing Report</h1>
            <div class="subtitle">Professional Security Assessment</div>
            <div class="subtitle">Report ID: ${reportId}</div>
        </div>

        <div class="info-grid">
            <div class="info-card">
                <h3>👤 Penetration Tester</h3>
                <p>${scanData.pentester || 'Security Analyst'}</p>
            </div>
            <div class="info-card">
                <h3>🎯 Target</h3>
                <p>${scanData.target}</p>
            </div>
            <div class="info-card">
                <h3>📅 Scan Date</h3>
                <p>${this.formatTimestamp(scanData.startTime)}</p>
            </div>
            <div class="info-card">
                <h3>⏱️ Duration</h3>
                <p>${scanData.duration || 'N/A'}</p>
            </div>
            <div class="info-card">
                <h3>🔧 Scan Type</h3>
                <p>${scanData.scanType}</p>
            </div>
            <div class="info-card">
                <h3>📊 Status</h3>
                <p style="color: ${scanData.status === 'Completed' ? '#38a169' : '#e53e3e'}">${scanData.status}</p>
            </div>
        </div>

        <div class="section">
            <h2>📈 Executive Summary</h2>
            <p style="font-size: 1.1em; line-height: 1.8; background: #f7fafc; padding: 20px; border-radius: 8px;">
                ${analysis.summary}
            </p>
        </div>

        <div class="section">
            <h2>📊 Scan Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">${analysis.hostsFound}</div>
                    <div class="stat-label">Hosts Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">${analysis.portsOpen}</div>
                    <div class="stat-label">Open Ports</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">${analysis.services.length}</div>
                    <div class="stat-label">Services Detected</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">${analysis.vulnerabilities.length}</div>
                    <div class="stat-label">Security Notes</div>
                </div>
            </div>
        </div>

        ${analysis.services.length > 0 ? `
        <div class="section">
            <h2>🔍 Discovered Services</h2>
            <table class="services-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${analysis.services.map(service => `
                    <tr>
                        <td><strong>${service.port}</strong></td>
                        <td>${service.service}</td>
                        <td><span style="color: #38a169; font-weight: bold;">Open</span></td>
                    </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
        ` : ''}

        ${analysis.vulnerabilities.length > 0 ? `
        <div class="section">
            <h2>⚠️ Security Considerations</h2>
            ${analysis.vulnerabilities.map((vuln, index) => `
            <div class="vulnerability severity-medium">
                <h4>Security Note #${index + 1}</h4>
                <p>${vuln}</p>
            </div>
            `).join('')}
        </div>
        ` : ''}

        <div class="section">
            <h2>💻 Raw Scan Output</h2>
            <div class="command-output">${scanData.output}</div>
        </div>

        <div class="footer">
            <p><strong>Generated by Automated Penetration Testing Tool</strong></p>
            <p>Report generated on ${this.formatTimestamp()}</p>
            <p>⚠️ This report is confidential and intended for authorized personnel only</p>
        </div>
    </div>
</body>
</html>`;
    }

    async saveReport(scanData, format = 'html') {
        try {
            await this.ensureReportsDir();
            
            const reportId = this.generateReportId();
            // Use professional filename generation
            const filename = this.generateProfessionalFilename(scanData, format);
            const filepath = path.join(this.reportsDir, filename);

            let content;
            let writeMode = 'utf8';
            
            if (format === 'pdf') {
                content = await this.generatePDFReport(scanData);
                writeMode = null; // Binary for PDF
            } else if (format === 'html') {
                content = this.generateHTMLReport(scanData);
            } else {
                // Fallback to text format
                content = this.generateTextReport(scanData);
            }

            if (format === 'pdf') {
                // Convert ArrayBuffer to Buffer for PDF files
                const buffer = Buffer.from(content);
                await fs.writeFile(filepath, buffer);
            } else {
                await fs.writeFile(filepath, content, 'utf8');
            }
            
            return {
                success: true,
                filename,
                filepath,
                reportId,
                size: content.length
            };
        } catch (error) {
            console.error('Error saving report:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    generateTextReport(scanData) {
        const analysis = this.parseNmapOutput(scanData.output);
        const reportId = this.generateReportId();
        
        return `
PENETRATION TESTING REPORT
==========================

Report ID: ${reportId}
Generated: ${this.formatTimestamp()}

SCAN INFORMATION
================
Penetration Tester: ${scanData.pentester || 'Security Analyst'}
Target: ${scanData.target}
Scan Date: ${this.formatTimestamp(scanData.startTime)}
Duration: ${scanData.duration || 'N/A'}
Scan Type: ${scanData.scanType}
Status: ${scanData.status}

EXECUTIVE SUMMARY
=================
${analysis.summary}

SCAN STATISTICS
===============
Hosts Found: ${analysis.hostsFound}
Open Ports: ${analysis.portsOpen}
Services Detected: ${analysis.services.length}
Security Notes: ${analysis.vulnerabilities.length}

DISCOVERED SERVICES
===================
${analysis.services.length > 0 ? 
    analysis.services.map(service => `${service.port} - ${service.service} (Open)`).join('\n') :
    'No services discovered'
}

SECURITY CONSIDERATIONS
=======================
${analysis.vulnerabilities.length > 0 ?
    analysis.vulnerabilities.map((vuln, index) => `${index + 1}. ${vuln}`).join('\n') :
    'No immediate security concerns identified'
}

RAW SCAN OUTPUT
===============
${scanData.output}

---
Report generated by Automated Penetration Testing Tool
This report is confidential and intended for authorized personnel only
        `;
    }

    async getReports() {
        try {
            await this.ensureReportsDir();
            const files = await fs.readdir(this.reportsDir);
            const reports = [];

            for (const file of files) {
                if (file.endsWith('.html') || file.endsWith('.txt') || file.endsWith('.pdf')) {
                    const filepath = path.join(this.reportsDir, file);
                    const stats = await fs.stat(filepath);
                    
                    // Extract metadata from filename
                    const nameParts = file.split('_');
                    const target = nameParts.length > 2 ? 'Unknown' : 'Unknown';
                    
                    reports.push({
                        filename: file,
                        size: stats.size,
                        created: stats.birthtime,
                        modified: stats.mtime,
                        type: path.extname(file).slice(1).toUpperCase(),
                        target: target,
                        pentester: 'Security Analyst'
                    });
                }
            }

            return reports.sort((a, b) => b.created - a.created);
        } catch (error) {
            console.error('Error getting reports:', error);
            return [];
        }
    }
}

module.exports = ReportGenerator;
