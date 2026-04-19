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
            if (!scanData) {
                throw new Error('Scan data is required for PDF generation');
            }

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

            const doc = new jsPDF({
                orientation: 'portrait',
                unit: 'mm',
                format: 'a4'
            });

            const pageWidth = doc.internal.pageSize.getWidth();
            const pageHeight = doc.internal.pageSize.getHeight();
            const margin = 15;
            const contentWidth = pageWidth - (2 * margin);
            let currentY = margin;

            const colors = {
                primary: [0, 100, 200],
                secondary: [100, 100, 100],
                success: [40, 167, 69],
                warning: [255, 193, 7],
                danger: [220, 53, 69],
                info: [23, 162, 184],
                dark: [33, 37, 41],
                light: [248, 249, 250],
                text: [52, 58, 64],
                gridLine: [220, 220, 220],
                headerBg: [41, 98, 255],
                cardBg: [250, 250, 250]
            };

            const addText = (text, x, y, maxWidth = contentWidth, fontSize = 10, fontStyle = 'normal', textColor = colors.text) => {
                try {
                    doc.setFontSize(fontSize);
                    doc.setFont(undefined, fontStyle);
                    doc.setTextColor(textColor[0], textColor[1], textColor[2]);
                    const safeText = String(text || '').replace(/[^\x00-\x7F]/g, '?');
                    const splitText = doc.splitTextToSize(safeText, maxWidth);
                    doc.text(splitText, x, y);
                    return y + (splitText.length * (fontSize * 0.45));
                } catch (e) {
                    return y + fontSize;
                }
            };

            const drawRect = (x, y, w, h, fillColor, strokeColor = null) => {
                if (fillColor) {
                    doc.setFillColor(fillColor[0], fillColor[1], fillColor[2]);
                }
                if (strokeColor) {
                    doc.setDrawColor(strokeColor[0], strokeColor[1], strokeColor[2]);
                    doc.rect(x, y, w, h, 'FD');
                } else {
                    doc.rect(x, y, w, h, 'F');
                }
            };

            const drawLine = (x1, y1, x2, y2, color = colors.gridLine, width = 0.5) => {
                doc.setDrawColor(color[0], color[1], color[2]);
                doc.setLineWidth(width);
                doc.line(x1, y1, x2, y2);
            };

            const checkNewPage = (neededHeight) => {
                if (currentY + neededHeight > pageHeight - 30) {
                    doc.addPage();
                    currentY = margin;
                    return true;
                }
                return false;
            };

            const drawHeader = () => {
                doc.setFillColor(colors.headerBg[0], colors.headerBg[1], colors.headerBg[2]);
                doc.rect(0, 0, pageWidth, 35, 'F');

                doc.setTextColor(255, 255, 255);
                doc.setFontSize(22);
                doc.setFont(undefined, 'bold');
                doc.text('PENETRATION TESTING REPORT', pageWidth / 2, 15, { align: 'center' });

                doc.setFontSize(10);
                doc.setFont(undefined, 'normal');
                doc.text('Professional Security Assessment', pageWidth / 2, 23, { align: 'center' });

                doc.setFontSize(8);
                doc.text(`Report ID: ${reportId}`, pageWidth / 2, 31, { align: 'center' });

                currentY = 45;
            };

            const drawFooter = (pageNum, totalPages) => {
                doc.setFontSize(8);
                doc.setTextColor(128, 128, 128);
                doc.text(`Page ${pageNum} of ${totalPages}`, pageWidth / 2, pageHeight - 10, { align: 'center' });
                doc.text(`Generated by AutoPentrix | ${new Date().toLocaleString()}`, pageWidth / 2, pageHeight - 6, { align: 'center' });
            };

            const drawCard = (title, contentY, contentHeight) => {
                checkNewPage(contentHeight + 20);

                drawRect(margin, currentY, contentWidth, contentHeight + 15, colors.cardBg, colors.gridLine);

                doc.setFillColor(colors.primary[0], colors.primary[1], colors.primary[2]);
                doc.rect(margin, currentY, contentWidth, 10, 'F');

                doc.setTextColor(255, 255, 255);
                doc.setFontSize(11);
                doc.setFont(undefined, 'bold');
                doc.text(title, margin + 5, currentY + 7);

                currentY += 15;
                return currentY;
            };

            drawHeader();

            doc.setTextColor(colors.text[0], colors.text[1], colors.text[2]);

            const infoCardY = currentY;
            const infoCardHeight = 35;
            drawRect(margin, infoCardY, contentWidth, infoCardHeight, colors.cardBg, colors.gridLine);

            doc.setFillColor(colors.dark[0], colors.dark[1], colors.dark[2]);
            doc.rect(margin, infoCardY, contentWidth, 8, 'F');
            doc.setTextColor(255, 255, 255);
            doc.setFontSize(9);
            doc.setFont(undefined, 'bold');
            doc.text('SCAN INFORMATION', margin + 3, infoCardY + 5.5);

            currentY = infoCardY + 12;
            doc.setTextColor(colors.text[0], colors.text[1], colors.text[2]);

            const col1X = margin + 5;
            const col2X = margin + contentWidth / 2 + 5;

            currentY = addText(`Pentester: ${safeData.pentester}`, col1X, currentY, contentWidth / 2 - 5, 9, 'normal') + 1;
            currentY = addText(`Target: ${safeData.target}`, col1X, currentY, contentWidth / 2 - 5, 9, 'normal') + 1;
            currentY = addText(`Scan Date: ${this.formatTimestamp(new Date(safeData.startTime))}`, col1X, currentY, contentWidth / 2 - 5, 9, 'normal') + 1;

            const tempY = infoCardY + 12;
            currentY = addText(`Duration: ${safeData.duration}`, col2X, tempY, contentWidth / 2 - 5, 9, 'normal') + 1;
            currentY = addText(`Scan Type: ${safeData.scanType}`, col2X, currentY, contentWidth / 2 - 5, 9, 'normal') + 1;
            currentY = addText(`Status: ${safeData.status}`, col2X, currentY, contentWidth / 2 - 5, 9, 'normal') + 5;

            currentY += 8;

            const summaryCardY = currentY;
            checkNewPage(50);
            drawRect(margin, summaryCardY, contentWidth, 30, colors.cardBg, colors.gridLine);

            doc.setFillColor(colors.dark[0], colors.dark[1], colors.dark[2]);
            doc.rect(margin, summaryCardY, contentWidth, 10, 'F');
            doc.setTextColor(255, 255, 255);
            doc.setFontSize(9);
            doc.setFont(undefined, 'bold');
            doc.text('EXECUTIVE SUMMARY', margin + 3, summaryCardY + 7);

            currentY = summaryCardY + 14;
            doc.setTextColor(colors.text[0], colors.text[1], colors.text[2]);
            currentY = addText(analysis.summary, margin + 5, currentY, contentWidth - 10, 9, 'normal') + 5;

            currentY += 5;

            checkNewPage(80);
            currentY = drawCard('SCAN STATISTICS', currentY, 35);

            const statBoxWidth = (contentWidth - 15) / 4;
            const stats = [
                { label: 'Hosts Found', value: analysis.hostsFound, color: colors.primary },
                { label: 'Open Ports', value: analysis.portsOpen, color: colors.success },
                { label: 'Services', value: analysis.services.length, color: colors.info },
                { label: 'Vulnerabilities', value: analysis.vulnerabilities.length, color: colors.warning }
            ];

            stats.forEach((stat, i) => {
                const boxX = margin + 3 + (i * statBoxWidth);
                const boxY = currentY;
                const boxHeight = 25;

                drawRect(boxX, boxY, statBoxWidth - 3, boxHeight, [255, 255, 255], stat.color);

                doc.setTextColor(stat.color[0], stat.color[1], stat.color[2]);
                doc.setFontSize(18);
                doc.setFont(undefined, 'bold');
                doc.text(String(stat.value), boxX + statBoxWidth / 2 - 3, boxY + 12, { align: 'center' });

                doc.setTextColor(colors.text[0], colors.text[1], colors.text[2]);
                doc.setFontSize(7);
                doc.setFont(undefined, 'normal');
                doc.text(stat.label, boxX + statBoxWidth / 2 - 3, boxY + 20, { align: 'center' });
            });

            currentY += 30;

            checkNewPage(80);
            currentY = drawCard('PORT DISTRIBUTION', currentY, 50);

            if (analysis.services.length > 0) {
                const portCounts = {};
                analysis.services.forEach(svc => {
                    const serviceName = svc.service.toLowerCase();
                    portCounts[serviceName] = (portCounts[serviceName] || 0) + 1;
                });

                const sortedPorts = Object.entries(portCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
                const barHeight = 6;
                const maxBarWidth = contentWidth - 80;

                sortedPorts.forEach(([port, count], i) => {
                    const barY = currentY + (i * (barHeight + 3));
                    const barWidth = Math.min((count / sortedPorts[0][1]) * maxBarWidth, maxBarWidth);

                    doc.setFontSize(8);
                    doc.setFont(undefined, 'normal');
                    doc.setTextColor(colors.text[0], colors.text[1], colors.text[2]);
                    doc.text(port.substring(0, 15), margin + 5, barY + 4);

                    drawRect(margin + 45, barY - 2, barWidth, barHeight, colors.primary);

                    doc.setTextColor(255, 255, 255);
                    doc.setFontSize(7);
                    doc.text(String(count), margin + 45 + barWidth / 2, barY + 3.5, { align: 'center' });
                });

                currentY += sortedPorts.length * (barHeight + 3) + 5;
            } else {
                currentY = addText('No services detected.', margin + 5, currentY, contentWidth - 10, 9, 'italic') + 5;
            }

            if (analysis.services.length > 0) {
                checkNewPage(80);
                currentY = drawCard('SERVICES OVERVIEW BY PORT RANGE', currentY, 35);

                const portRanges = {
                    'Well-Known (0-1023)': 0,
                    'Registered (1024-49151)': 0,
                    'Dynamic (49152+)': 0
                };

                analysis.services.forEach(svc => {
                    const port = parseInt(svc.port.split('/')[0]);
                    if (port <= 1023) portRanges['Well-Known (0-1023)']++;
                    else if (port <= 49151) portRanges['Registered (1024-49151)']++;
                    else portRanges['Dynamic (49152+)']++;
                });

                const rangeColors = [colors.success, colors.info, colors.warning];
                const rangeBoxWidth = (contentWidth - 10) / 3;
                let rangeIndex = 0;

                for (const [range, count] of Object.entries(portRanges)) {
                    const boxX = margin + 3 + (rangeIndex * rangeBoxWidth);
                    const boxY = currentY;
                    const boxHeight = 25;

                    drawRect(boxX, boxY, rangeBoxWidth - 3, boxHeight, [255, 255, 255], rangeColors[rangeIndex]);

                    doc.setTextColor(rangeColors[rangeIndex][0], rangeColors[rangeIndex][1], rangeColors[rangeIndex][2]);
                    doc.setFontSize(12);
                    doc.setFont(undefined, 'bold');
                    doc.text(String(count), boxX + rangeBoxWidth / 2 - 3, boxY + 12, { align: 'center' });

                    doc.setTextColor(colors.text[0], colors.text[1], colors.text[2]);
                    doc.setFontSize(6);
                    doc.setFont(undefined, 'normal');
                    doc.text(range, boxX + rangeBoxWidth / 2 - 3, boxY + 20, { align: 'center' });

                    rangeIndex++;
                }

                currentY += 30;
            }

            if (analysis.vulnerabilities.length > 0) {
                checkNewPage(100);
                currentY = drawCard('SECURITY CONSIDERATIONS & RECOMMENDATIONS', currentY, 60);

                const vulnInfo = {
                    'ssh': { risk: 'MEDIUM', name: 'SSH', damages: ['Brute-force attacks', 'Weak credentials'], recommendations: ['Use key-based auth', 'Disable root login', 'Implement fail2ban'] },
                    'http': { risk: 'HIGH', name: 'HTTP', damages: ['Data interception', 'Session hijacking'], recommendations: ['Enable HTTPS', 'Implement HSTS', 'Use TLS 1.2+'] },
                    'https': { risk: 'LOW', name: 'HTTPS', damages: ['SSL/TLS vulnerabilities'], recommendations: ['Use TLS 1.3', 'Regular cert renewal'] },
                    'ftp': { risk: 'HIGH', name: 'FTP', damages: ['Credential theft', 'Data interception'], recommendations: ['Use SFTP/SCP', 'Disable anonymous access'] },
                    'telnet': { risk: 'CRITICAL', name: 'Telnet', damages: ['Complete credential compromise', 'Session hijacking'], recommendations: ['Disable immediately', 'Use SSH instead'] },
                    'smtp': { risk: 'MEDIUM', name: 'SMTP', damages: ['Open relay', 'User enumeration'], recommendations: ['Restrict relay', 'Implement SPF/DKIM'] },
                    'dns': { risk: 'MEDIUM', name: 'DNS', damages: ['Cache poisoning', 'Zone transfers'], recommendations: ['Disable zone transfers', 'Implement DNSSEC'] },
                    'msrpc': { risk: 'HIGH', name: 'MS RPC', damages: ['Remote code execution', 'Lateral movement'], recommendations: ['Block port 135', 'Apply patches'] },
                    'netbios': { risk: 'HIGH', name: 'NetBIOS', damages: ['Network enumeration', 'SMB relay'], recommendations: ['Disable NetBIOS', 'Block ports 137-139'] },
                    'smb': { risk: 'CRITICAL', name: 'SMB', damages: ['EternalBlue exploits', 'Ransomware delivery'], recommendations: ['Block port 445', 'Apply MS17-010 patch', 'Disable SMBv1'] },
                    'rdp': { risk: 'CRITICAL', name: 'RDP', damages: ['BlueKeep', 'Brute-force', 'Ransomware'], recommendations: ['Enable NLA', 'Use VPN', 'Strong passwords'] }
                };

                analysis.vulnerabilities.forEach((vuln, idx) => {
                    checkNewPage(35);

                    const vulnKey = Object.keys(vulnInfo).find(key => vuln.toLowerCase().includes(key));
                    const info = vulnKey ? vulnInfo[vulnKey] : { risk: 'MEDIUM', name: 'Unknown', damages: [], recommendations: [] };

                    const riskColor = info.risk === 'CRITICAL' ? colors.danger : info.risk === 'HIGH' ? colors.warning : colors.info;

                    doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
                    doc.rect(margin + 3, currentY - 3, 3, 12, 'F');

                    doc.setTextColor(colors.dark[0], colors.dark[1], colors.dark[2]);
                    doc.setFontSize(9);
                    doc.setFont(undefined, 'bold');
                    doc.text(`${idx + 1}. ${info.name} - ${info.risk} RISK`, margin + 10, currentY + 3);

                    currentY += 8;
                    doc.setFont(undefined, 'normal');
                    doc.setFontSize(8);

                    currentY = addText(`Damages: ${info.damages.join(', ')}`, margin + 10, currentY, contentWidth - 15, 8, 'normal') + 1;
                    currentY = addText(`Recommendations: ${info.recommendations.join(', ')}`, margin + 10, currentY, contentWidth - 15, 8, 'normal', colors.success) + 5;
                });
            }

            if (analysis.services.length > 0) {
                checkNewPage(80);
                currentY = drawCard('DISCOVERED SERVICES', currentY, 50);

                const serviceColors = [colors.primary, colors.success, colors.info, colors.warning, colors.secondary];
                const servicesPerRow = 2;
                const serviceBoxWidth = (contentWidth - 10) / servicesPerRow;

                for (let i = 0; i < analysis.services.length && i < 10; i++) {
                    const svc = analysis.services[i];
                    const row = Math.floor(i / servicesPerRow);
                    const col = i % servicesPerRow;
                    const boxX = margin + 3 + (col * serviceBoxWidth);
                    const boxY = currentY + (row * 18);

                    if (boxY + 18 > pageHeight - 30) break;

                    drawRect(boxX, boxY, serviceBoxWidth - 3, 15, [255, 255, 255], serviceColors[i % serviceColors.length]);

                    doc.setTextColor(serviceColors[i % serviceColors.length][0], serviceColors[i % serviceColors.length][1], serviceColors[i % serviceColors.length][2]);
                    doc.setFontSize(9);
                    doc.setFont(undefined, 'bold');
                    doc.text(`Port ${svc.port}`, boxX + 3, boxY + 6);

                    doc.setTextColor(colors.text[0], colors.text[1], colors.text[2]);
                    doc.setFontSize(8);
                    doc.setFont(undefined, 'normal');
                    doc.text(svc.service, boxX + 3, boxY + 12);
                }

                currentY += Math.ceil(Math.min(analysis.services.length, 10) / servicesPerRow) * 18 + 5;
            }

            checkNewPage(100);
            currentY = drawCard('RAW SCAN OUTPUT', currentY, 80);

            doc.setFontSize(7);
            doc.setFont(undefined, 'normal');
            doc.setTextColor(colors.secondary[0], colors.secondary[1], colors.secondary[2]);

            const outputLines = safeData.output.split('\n').slice(0, 100);
            outputLines.forEach((line, idx) => {
                checkNewPage(5);
                const cleanLine = String(line).replace(/[^\x00-\x7F]/g, '?').substring(0, 120);
                doc.text(`${idx + 1}. ${cleanLine}`, margin + 5, currentY);
                currentY += 4;
            });

            if (safeData.output.split('\n').length > 100) {
                currentY += 3;
                doc.setTextColor(colors.warning[0], colors.warning[1], colors.warning[2]);
                doc.text(`[Output truncated - ${safeData.output.split('\n').length - 100} additional lines not shown]`, margin + 5, currentY);
            }

            const totalPages = doc.internal.getNumberOfPages();
            for (let i = 1; i <= totalPages; i++) {
                doc.setPage(i);
                drawFooter(i, totalPages);
            }

            return doc.output('arraybuffer');
        } catch (error) {
            console.error("PDF Generation Failed:", error);
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
                    // Format: ReportType_Target_Date_Time_PentesterName.ext
                    const baseName = path.parse(file).name;
                    const nameParts = baseName.split('_');
                    
                    let scanType = 'Network Scan';
                    let target = 'Unknown';
                    let pentester = 'Security Analyst';
                    
                    if (nameParts.length >= 5) {
                        scanType = nameParts[0].replace(/-/g, ' ');
                        target = nameParts[1];
                        // Pentester name is everything from part 4 onwards
                        pentester = nameParts.slice(4).join(' ').replace(/-/g, ' ');
                    }
                    
                    reports.push({
                        filename: file,
                        size: stats.size,
                        created: stats.birthtime,
                        modified: stats.mtime,
                        type: path.extname(file).slice(1).toUpperCase(),
                        target: target,
                        scanType: scanType,
                        pentester: pentester
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
