/**
 * Enhanced IDS Engine for IoT and ICS/SCADA Environments
 * Implements comprehensive threat detection with Suricata/Snort compatible rules
 * Author: Penetration Testing Tool Enhanced Edition
 */

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class IoTICSIDSEngine extends EventEmitter {
    constructor() {
        super();
        this.isMonitoring = false;
        this.threats = [];
        this.alerts = [];
        this.detectionRules = new Map();
        this.networkConfig = {
            HOME_NET: '192.168.0.0/16,10.0.0.0/8,172.16.0.0/12',
            AUTHORIZED_ICS_NET: '192.168.1.100/32,192.168.1.101/32',
            EXTERNAL_NET: '!$HOME_NET'
        };
        this.statistics = {
            totalThreats: 0,
            threatsLast24h: 0,
            severityDistribution: {
                CRITICAL: 0,
                HIGH: 0,
                MEDIUM: 0,
                LOW: 0
            },
            protocolBreakdown: {
                modbus: 0,
                dnp3: 0,
                mqtt: 0,
                http: 0,
                ssh: 0,
                other: 0
            }
        };
        
        this.initializeRules();
        this.startTimeStamp = Date.now();
        
        // Simulate real-time monitoring with sample data generation
        this.simulationInterval = null;
        this.fileMonitoringActive = false;
    }
    
    /**
     * Initialize comprehensive IoT/ICS detection rules
     */
    initializeRules() {
        // IoT Threat Detection Rules
        this.addRule('ssh_brute_force', {
            category: 'IoT',
            severity: 'HIGH',
            protocol: 'tcp',
            port: 22,
            description: 'SSH Brute Force Attack Detected',
            pattern: /SSH-.*failed/i,
            threshold: { count: 5, seconds: 60 },
            action: 'alert'
        });
        
        this.addRule('http_brute_force', {
            category: 'IoT',
            severity: 'HIGH',
            protocol: 'tcp',
            ports: [80, 443, 8080, 8443],
            description: 'HTTP/HTTPS Brute Force on IoT Management Interface',
            pattern: /POST\s+\/(login|admin|api\/auth)/i,
            threshold: { count: 10, seconds: 120 },
            action: 'alert'
        });
        
        this.addRule('dns_tunneling', {
            category: 'IoT',
            severity: 'MEDIUM',
            protocol: 'udp',
            port: 53,
            description: 'Potential DNS Tunneling Detected',
            pattern: /query.*length\s*>\s*50/i,
            threshold: { count: 3, seconds: 300 },
            action: 'alert'
        });
        
        this.addRule('firmware_upload', {
            category: 'IoT',
            severity: 'CRITICAL',
            protocol: 'tcp',
            description: 'Unauthorized Firmware Update Attempt',
            pattern: /\/(firmware|update|upgrade).*\.(bin|img|fw|hex)$/i,
            action: 'alert'
        });
        
        this.addRule('high_freq_telemetry', {
            category: 'IoT',
            severity: 'MEDIUM',
            protocol: 'tcp',
            ports: [80, 443, 8883, 1883],
            description: 'High Frequency Data Exfiltration',
            threshold: { count: 50, seconds: 60 },
            action: 'alert'
        });
        
        this.addRule('iot_port_scan', {
            category: 'IoT',
            severity: 'MEDIUM',
            protocol: 'tcp',
            ports: [23, 80, 443, 502, 2404, 8080, 8443, 9100],
            description: 'IoT Port Scan Detected',
            threshold: { count: 5, seconds: 60 },
            action: 'alert'
        });
        
        this.addRule('mqtt_unauthorized', {
            category: 'IoT',
            severity: 'MEDIUM',
            protocol: 'tcp',
            ports: [1883, 8883],
            description: 'Unauthorized MQTT Operations',
            threshold: { count: 20, seconds: 300 },
            action: 'alert'
        });
        
        // ICS/SCADA Threat Detection Rules
        this.addRule('modbus_write_unauthorized', {
            category: 'ICS',
            severity: 'CRITICAL',
            protocol: 'tcp',
            port: 502,
            description: 'Unauthorized Modbus Write Command',
            pattern: /modbus.*write.*function.*0x06/i,
            action: 'drop'
        });
        
        this.addRule('modbus_invalid_function', {
            category: 'ICS',
            severity: 'HIGH',
            protocol: 'tcp',
            port: 502,
            description: 'Invalid Modbus Function Code',
            pattern: /modbus.*function.*0x[8-F][0-F]/i,
            action: 'alert'
        });
        
        this.addRule('dnp3_unauthorized_control', {
            category: 'ICS',
            severity: 'CRITICAL',
            protocol: 'tcp',
            port: 20000,
            description: 'DNP3 Unauthorized Control Command',
            pattern: /dnp3.*control.*operation/i,
            action: 'drop'
        });
        
        this.addRule('scada_off_hours_access', {
            category: 'ICS',
            severity: 'HIGH',
            protocol: 'tcp',
            ports: [502, 2404, 44818],
            description: 'Off-Hours SCADA Register Access',
            timeRestriction: { start: '18:00', end: '06:00' },
            action: 'alert'
        });
        
        this.addRule('plc_rapid_changes', {
            category: 'ICS',
            severity: 'HIGH',
            protocol: 'tcp',
            port: 502,
            description: 'Rapid PLC State Changes Detected',
            threshold: { count: 10, seconds: 30 },
            action: 'alert'
        });
        
        this.addRule('ethernet_ip_config', {
            category: 'ICS',
            severity: 'CRITICAL',
            protocol: 'tcp',
            port: 44818,
            description: 'EtherNet/IP Configuration Change',
            pattern: /ethernet.*ip.*config.*change/i,
            action: 'alert'
        });
        
        // File System Monitoring Rules
        this.addRule('file_copy_operation', {
            category: 'File',
            severity: 'MEDIUM',
            protocol: 'tcp',
            ports: [139, 445],
            description: 'File Copy Operation Detected',
            pattern: /SMB.*copy|file.*copied/i,
            action: 'alert'
        });
        
        this.addRule('file_modification', {
            category: 'File',
            severity: 'HIGH',
            protocol: 'tcp',
            ports: [139, 445],
            description: 'Critical File Modification Detected',
            pattern: /file.*modified.*\.(cfg|conf|ini|exe|dll)/i,
            action: 'alert'
        });
        
        this.addRule('file_deletion', {
            category: 'File',
            severity: 'HIGH',
            protocol: 'tcp',
            ports: [139, 445],
            description: 'File Deletion Detected',
            pattern: /file.*deleted|delete.*operation/i,
            action: 'alert'
        });
        
        // Advanced Persistent Threats
        this.addRule('encrypted_c2_pattern', {
            category: 'APT',
            severity: 'HIGH',
            protocol: 'tcp',
            ports: [443, 993, 995],
            description: 'Suspicious Encrypted C2 Pattern',
            threshold: { count: 5, seconds: 300 },
            action: 'alert'
        });
        
        this.addRule('lateral_movement', {
            category: 'APT',
            severity: 'HIGH',
            protocol: 'tcp',
            ports: [135, 139, 445, 3389, 5985],
            description: 'Potential Lateral Movement',
            threshold: { count: 10, seconds: 300 },
            action: 'alert'
        });
        
        // False Data Injection Detection
        this.addRule('temperature_anomaly', {
            category: 'FDI',
            severity: 'CRITICAL',
            protocol: 'tcp',
            port: 502,
            description: 'Temperature Sensor Anomaly - Out of Range',
            pattern: /temperature.*[>]?\s*[8-9]\d{3,}|temperature.*[-]\d{3,}/i,
            action: 'alert'
        });
        
        this.addRule('pressure_manipulation', {
            category: 'FDI',
            severity: 'CRITICAL',
            protocol: 'tcp',
            port: 502,
            description: 'Pressure Sensor Data Manipulation',
            pattern: /pressure.*6[5-9]\d{3,}|pressure.*0\.0+$/i,
            threshold: { count: 3, seconds: 60 },
            action: 'alert'
        });
    }
    
    /**
     * Add a new detection rule
     */
    addRule(ruleId, ruleConfig) {
        ruleConfig.id = ruleId;
        ruleConfig.created = new Date().toISOString();
        ruleConfig.hitCount = 0;
        ruleConfig.lastTriggered = null;
        this.detectionRules.set(ruleId, ruleConfig);
    }
    
    /**
     * Start IDS monitoring
     */
    startMonitoring() {
        if (this.isMonitoring) {
            return { success: false, message: 'IDS is already monitoring' };
        }
        
        this.isMonitoring = true;
        this.startTimeStamp = Date.now();
        
        // Start simulated monitoring
        this.simulationInterval = setInterval(() => {
            this.simulateTrafficAnalysis();
        }, 5000); // Check every 5 seconds
        
        // Start file monitoring
        this.startFileMonitoring();
        
        this.emit('log-entry', {
            timestamp: new Date().toISOString(),
            level: 'INFO',
            message: 'IoT/ICS IDS Engine started monitoring',
            component: 'IDSEngine'
        });
        
        return { success: true, message: 'IDS monitoring started successfully' };
    }
    
    /**
     * Stop IDS monitoring
     */
    stopMonitoring() {
        if (!this.isMonitoring) {
            return { success: false, message: 'IDS is not currently monitoring' };
        }
        
        this.isMonitoring = false;
        
        if (this.simulationInterval) {
            clearInterval(this.simulationInterval);
            this.simulationInterval = null;
        }
        
        this.stopFileMonitoring();
        
        this.emit('log-entry', {
            timestamp: new Date().toISOString(),
            level: 'INFO',
            message: 'IoT/ICS IDS Engine stopped monitoring',
            component: 'IDSEngine'
        });
        
        return { success: true, message: 'IDS monitoring stopped successfully' };
    }
    
    /**
     * Simulate traffic analysis and threat detection
     */
    simulateTrafficAnalysis() {
        if (!this.isMonitoring) return;
        
        // Randomly generate threats based on rules
        const ruleIds = Array.from(this.detectionRules.keys());
        
        // Generate threats with realistic probability
        if (Math.random() < 0.15) { // 15% chance every 5 seconds
            const randomRuleId = ruleIds[Math.floor(Math.random() * ruleIds.length)];
            const rule = this.detectionRules.get(randomRuleId);
            
            this.generateThreat(rule);
        }
        
        // Occasionally generate file system events
        if (Math.random() < 0.08) { // 8% chance
            this.generateFileSystemEvent();
        }
    }
    
    /**
     * Generate a realistic threat based on a rule
     */
    generateThreat(rule) {
        const threatId = this.generateThreatId();
        const sourceIPs = [
            '192.168.1.150', '10.0.0.45', '172.16.0.100',
            '203.0.113.10', '198.51.100.25', '192.0.2.50'
        ];
        const targetIPs = [
            '192.168.1.10', '192.168.1.20', '10.0.1.5',
            '172.16.1.100', '192.168.100.50'
        ];
        
        const threat = {
            id: threatId,
            ruleId: rule.id,
            type: rule.category.toLowerCase(),
            severity: rule.severity,
            description: rule.description,
            source: sourceIPs[Math.floor(Math.random() * sourceIPs.length)],
            target: targetIPs[Math.floor(Math.random() * targetIPs.length)],
            protocol: rule.protocol,
            port: Array.isArray(rule.ports) ? rule.ports[0] : (rule.port || 'unknown'),
            detected_at: new Date().toISOString(),
            status: 'ACTIVE',
            confidence: Math.floor(Math.random() * 30 + 70), // 70-100%
            details: this.generateThreatDetails(rule),
            actions_taken: rule.action === 'drop' ? ['BLOCKED'] : ['LOGGED'],
            false_positive_likelihood: Math.floor(Math.random() * 20 + 5) // 5-25%
        };
        
        // Update rule statistics
        rule.hitCount++;
        rule.lastTriggered = threat.detected_at;
        
        // Update global statistics
        this.statistics.totalThreats++;
        this.statistics.threatsLast24h++;
        this.statistics.severityDistribution[rule.severity]++;
        
        // Update protocol breakdown
        if (rule.port === 502 || rule.description.toLowerCase().includes('modbus')) {
            this.statistics.protocolBreakdown.modbus++;
        } else if (rule.port === 20000 || rule.description.toLowerCase().includes('dnp3')) {
            this.statistics.protocolBreakdown.dnp3++;
        } else if ([1883, 8883].includes(rule.port) || rule.description.toLowerCase().includes('mqtt')) {
            this.statistics.protocolBreakdown.mqtt++;
        } else if ([80, 443, 8080, 8443].includes(rule.port)) {
            this.statistics.protocolBreakdown.http++;
        } else if (rule.port === 22) {
            this.statistics.protocolBreakdown.ssh++;
        } else {
            this.statistics.protocolBreakdown.other++;
        }
        
        // Add to threats list
        this.threats.unshift(threat);
        
        // Keep only last 1000 threats
        if (this.threats.length > 1000) {
            this.threats = this.threats.slice(0, 1000);
        }
        
        // Emit threat event
        this.emit('threat-detected', threat);
        
        // Generate alert if severity is high enough
        if (['CRITICAL', 'HIGH'].includes(rule.severity)) {
            this.generateSecurityAlert(threat);
        }
        
        // Log the event
        this.emit('log-entry', {
            timestamp: threat.detected_at,
            level: rule.severity === 'CRITICAL' ? 'CRITICAL' : 'WARNING',
            message: `${rule.description} - Source: ${threat.source}, Target: ${threat.target}`,
            component: 'ThreatDetection',
            threatId: threatId
        });
    }
    
    /**
     * Generate detailed threat information
     */
    generateThreatDetails(rule) {
        const details = {
            rule_category: rule.category,
            detection_method: 'signature_based'
        };
        
        switch (rule.category) {
            case 'IoT':
                details.device_type = ['router', 'camera', 'sensor', 'gateway'][Math.floor(Math.random() * 4)];
                details.attack_vector = ['network', 'web_interface', 'protocol'][Math.floor(Math.random() * 3)];
                break;
            case 'ICS':
                details.system_type = ['PLC', 'HMI', 'SCADA_server', 'historian'][Math.floor(Math.random() * 4)];
                details.impact_level = ['process_disruption', 'data_corruption', 'safety_system'][Math.floor(Math.random() * 3)];
                break;
            case 'File':
                details.file_path = ['/etc/config/', 'C:\\Windows\\System32\\', '/var/log/', 'C:\\Program Files\\'][Math.floor(Math.random() * 4)];
                details.operation_type = ['read', 'write', 'delete', 'modify'][Math.floor(Math.random() * 4)];
                break;
            case 'APT':
                details.campaign_indicators = ['persistence', 'exfiltration', 'reconnaissance'][Math.floor(Math.random() * 3)];
                details.ttl_phase = ['initial_access', 'execution', 'persistence', 'collection'][Math.floor(Math.random() * 4)];
                break;
            case 'FDI':
                details.sensor_type = ['temperature', 'pressure', 'flow', 'level'][Math.floor(Math.random() * 4)];
                details.anomaly_magnitude = (Math.random() * 100).toFixed(2) + '%';
                break;
        }
        
        return details;
    }
    
    /**
     * Generate security alert
     */
    generateSecurityAlert(threat) {
        const alert = {
            id: 'ALERT-' + Date.now(),
            threatId: threat.id,
            severity: threat.severity,
            title: `${threat.severity} Security Alert: ${threat.description}`,
            message: `Detected ${threat.description} from ${threat.source} targeting ${threat.target}`,
            timestamp: new Date().toISOString(),
            status: 'ACTIVE',
            acknowledged: false,
            response_required: threat.severity === 'CRITICAL'
        };
        
        this.alerts.unshift(alert);
        
        // Keep only last 500 alerts
        if (this.alerts.length > 500) {
            this.alerts = this.alerts.slice(0, 500);
        }
        
        this.emit('security-alert', alert);
    }
    
    /**
     * Generate file system event
     */
    generateFileSystemEvent() {
        const operations = ['copy', 'move', 'modify', 'delete'];
        const filePaths = [
            'C:\\Windows\\System32\\config.ini',
            '/etc/modbus/modbus.conf',
            '/var/log/scada.log',
            'C:\\Program Files\\HMI\\config.xml',
            '/opt/plc/ladder.logic',
            'C:\\Users\\Administrator\\Documents\\backup.cfg'
        ];
        const users = ['Administrator', 'root', 'operator', 'maintenance', 'guest'];
        
        const operation = operations[Math.floor(Math.random() * operations.length)];
        const filePath = filePaths[Math.floor(Math.random() * filePaths.length)];
        const user = users[Math.floor(Math.random() * users.length)];
        
        const event = {
            id: 'FILE-' + Date.now(),
            type: 'file_system',
            operation: operation,
            file_path: filePath,
            user: user,
            timestamp: new Date().toISOString(),
            source_ip: '192.168.1.' + Math.floor(Math.random() * 200 + 10),
            severity: operation === 'delete' ? 'HIGH' : 'MEDIUM'
        };
        
        this.emit('log-entry', {
            timestamp: event.timestamp,
            level: 'WARNING',
            message: `File ${operation}: ${filePath} by user ${user}`,
            component: 'FileMonitor',
            eventId: event.id
        });
    }
    
    /**
     * Start file monitoring simulation
     */
    startFileMonitoring() {
        this.fileMonitoringActive = true;
        
        this.emit('log-entry', {
            timestamp: new Date().toISOString(),
            level: 'INFO',
            message: 'File system monitoring activated',
            component: 'FileMonitor'
        });
    }
    
    /**
     * Stop file monitoring
     */
    stopFileMonitoring() {
        this.fileMonitoringActive = false;
        
        this.emit('log-entry', {
            timestamp: new Date().toISOString(),
            level: 'INFO',
            message: 'File system monitoring deactivated',
            component: 'FileMonitor'
        });
    }
    
    /**
     * Generate unique threat ID
     */
    generateThreatId() {
        return 'THR-' + Date.now() + '-' + Math.random().toString(36).substr(2, 6).toUpperCase();
    }
    
    /**
     * Get system health status
     */
    getSystemHealth() {
        const uptime = Math.floor((Date.now() - this.startTimeStamp) / 1000);
        
        return {
            ids_status: this.isMonitoring ? 'ACTIVE' : 'INACTIVE',
            uptime: uptime,
            active_rules: this.detectionRules.size,
            threats_in_memory: this.threats.length,
            alerts_pending: this.alerts.filter(a => a.status === 'ACTIVE').length,
            file_monitoring: this.fileMonitoringActive ? 'ENABLED' : 'DISABLED',
            last_threat: this.threats.length > 0 ? this.threats[0].detected_at : null,
            memory_usage: Math.floor(Math.random() * 30 + 40) + '%', // Simulated
            cpu_usage: Math.floor(Math.random() * 20 + 10) + '%', // Simulated
            network_interfaces: ['eth0', 'wlan0'],
            rule_update_status: 'UP_TO_DATE'
        };
    }
    
    /**
     * Get recent threats
     */
    getRecentThreats(limit = 50) {
        return this.threats.slice(0, limit);
    }
    
    /**
     * Get threat statistics
     */
    getThreatStatistics() {
        const now = Date.now();
        const last24h = now - (24 * 60 * 60 * 1000);
        
        const threats24h = this.threats.filter(t => new Date(t.detected_at).getTime() > last24h);
        
        return {
            total_threats: this.statistics.totalThreats,
            threats_24h: threats24h.length,
            severity_distribution: this.statistics.severityDistribution,
            protocol_breakdown: this.statistics.protocolBreakdown,
            top_sources: this.getTopSources(),
            top_targets: this.getTopTargets(),
            detection_rate: this.calculateDetectionRate(),
            false_positive_rate: this.calculateFalsePositiveRate()
        };
    }
    
    /**
     * Get top threat sources
     */
    getTopSources() {
        const sourceMap = new Map();
        
        this.threats.forEach(threat => {
            const count = sourceMap.get(threat.source) || 0;
            sourceMap.set(threat.source, count + 1);
        });
        
        return Array.from(sourceMap.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([ip, count]) => ({ ip, count }));
    }
    
    /**
     * Get top threat targets
     */
    getTopTargets() {
        const targetMap = new Map();
        
        this.threats.forEach(threat => {
            const count = targetMap.get(threat.target) || 0;
            targetMap.set(threat.target, count + 1);
        });
        
        return Array.from(targetMap.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([ip, count]) => ({ ip, count }));
    }
    
    /**
     * Calculate detection rate
     */
    calculateDetectionRate() {
        // Simulated calculation
        return (Math.random() * 15 + 85).toFixed(2) + '%'; // 85-100%
    }
    
    /**
     * Calculate false positive rate
     */
    calculateFalsePositiveRate() {
        const avgFalsePositive = this.threats.reduce((acc, threat) => acc + threat.false_positive_likelihood, 0) / this.threats.length;
        return (avgFalsePositive || 10).toFixed(2) + '%';
    }
    
    /**
     * Update threat status
     */
    updateThreatStatus(threatId, status, resolution = null) {
        const threat = this.threats.find(t => t.id === threatId);
        
        if (threat) {
            threat.status = status;
            threat.resolution = resolution;
            threat.updated_at = new Date().toISOString();
            
            this.emit('log-entry', {
                timestamp: threat.updated_at,
                level: 'INFO',
                message: `Threat ${threatId} status updated to ${status}`,
                component: 'ThreatManagement'
            });
            
            return threat;
        }
        
        return null;
    }
    
    /**
     * Generate comprehensive threat report
     */
    generateThreatReport() {
        const stats = this.getThreatStatistics();
        const health = this.getSystemHealth();
        
        return {
            generated_at: new Date().toISOString(),
            report_id: 'RPT-' + Date.now(),
            system_health: health,
            statistics: stats,
            recent_threats: this.getRecentThreats(20),
            active_alerts: this.alerts.filter(a => a.status === 'ACTIVE').slice(0, 10),
            rule_effectiveness: this.calculateRuleEffectiveness(),
            recommendations: this.generateRecommendations(stats)
        };
    }
    
    /**
     * Calculate rule effectiveness
     */
    calculateRuleEffectiveness() {
        const effectiveness = [];
        
        for (const [ruleId, rule] of this.detectionRules.entries()) {
            effectiveness.push({
                rule_id: ruleId,
                description: rule.description,
                hit_count: rule.hitCount,
                last_triggered: rule.lastTriggered,
                effectiveness_score: Math.min(rule.hitCount * 10, 100) // Simple scoring
            });
        }
        
        return effectiveness.sort((a, b) => b.hit_count - a.hit_count);
    }
    
    /**
     * Generate security recommendations
     */
    generateRecommendations(stats) {
        const recommendations = [];
        
        if (stats.threats_24h > 50) {
            recommendations.push({
                priority: 'HIGH',
                title: 'High Threat Volume',
                description: 'Consider implementing additional network segmentation',
                action: 'Review network topology and implement micro-segmentation'
            });
        }
        
        if (stats.severity_distribution.CRITICAL > 0) {
            recommendations.push({
                priority: 'CRITICAL',
                title: 'Critical Threats Detected',
                description: 'Immediate investigation required for critical threats',
                action: 'Escalate to security team and isolate affected systems'
            });
        }
        
        if (stats.protocol_breakdown.modbus > stats.protocol_breakdown.http) {
            recommendations.push({
                priority: 'MEDIUM',
                title: 'Industrial Protocol Activity',
                description: 'High Modbus activity detected',
                action: 'Review and validate industrial protocol communications'
            });
        }
        
        recommendations.push({
            priority: 'LOW',
            title: 'Regular Maintenance',
            description: 'Perform regular rule updates and system maintenance',
            action: 'Schedule monthly security review and rule optimization'
        });
        
        return recommendations;
    }
    
    /**
     * Export rules to Suricata/Snort format
     */
    exportRulesToFile(format = 'suricata') {
        const rulesContent = this.generateRulesFile(format);
        const filename = `iot-ics-rules-${format}-${Date.now()}.rules`;
        const filepath = path.join(__dirname, '..', 'rules', filename);
        
        // Ensure rules directory exists
        const rulesDir = path.dirname(filepath);
        if (!fs.existsSync(rulesDir)) {
            fs.mkdirSync(rulesDir, { recursive: true });
        }
        
        fs.writeFileSync(filepath, rulesContent);
        
        return {
            success: true,
            filename: filename,
            filepath: filepath,
            rules_count: this.detectionRules.size
        };
    }
    
    /**
     * Generate rules file content
     */
    generateRulesFile(format) {
        let content = `# IoT/ICS/SCADA IDS Rules\n`;
        content += `# Generated by Penetration Testing Tool\n`;
        content += `# Format: ${format.toUpperCase()}\n`;
        content += `# Generated: ${new Date().toISOString()}\n\n`;
        
        let sid = 1000000; // Start SID counter
        
        for (const [ruleId, rule] of this.detectionRules.entries()) {
            content += `# ${rule.description}\n`;
            
            let ruleString = rule.action || 'alert';
            ruleString += ` ${rule.protocol} any any -> $HOME_NET`;
            
            if (rule.ports) {
                ruleString += ` [${rule.ports.join(',')}]`;
            } else if (rule.port) {
                ruleString += ` ${rule.port}`;
            } else {
                ruleString += ` any`;
            }
            
            ruleString += ` (msg:"${rule.description}"`;
            
            if (rule.pattern) {
                ruleString += `; pcre:"${rule.pattern.source}/${rule.pattern.flags}"`;
            }
            
            if (rule.threshold) {
                ruleString += `; threshold:type threshold, track by_src, count ${rule.threshold.count}, seconds ${rule.threshold.seconds}`;
            }
            
            ruleString += `; classtype:policy-violation; sid:${sid++}; rev:1;)`;
            
            content += ruleString + '\n\n';
        }
        
        return content;
    }
    
    /**
     * Add real-time connection
     */
    addRealtimeConnection(connectionId) {
        // Implementation for tracking real-time connections
        this.emit('log-entry', {
            timestamp: new Date().toISOString(),
            level: 'INFO',
            message: `Real-time connection added: ${connectionId}`,
            component: 'ConnectionManager'
        });
    }
    
    /**
     * Remove real-time connection
     */
    removeRealtimeConnection(connectionId) {
        // Implementation for removing real-time connections
        this.emit('log-entry', {
            timestamp: new Date().toISOString(),
            level: 'INFO',
            message: `Real-time connection removed: ${connectionId}`,
            component: 'ConnectionManager'
        });
    }
}

module.exports = IoTICSIDSEngine;
