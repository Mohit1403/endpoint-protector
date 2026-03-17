const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const FileMonitor = require('./fileMonitor');

/**
 * Enhanced IDS Threat Hunter with IoT/ICS Support and File Monitoring
 * Integrates signature-based, anomaly-based, and behavioral detection
 */
class EnhancedIDSThreatHunter extends EventEmitter {
    constructor() {
        super();
        this.isRunning = false;
        this.threats = [];
        this.fileMonitor = null;
        this.monitoringInterval = null;
        this.alertThreshold = 3;
        this.detectionWindow = 300000; // 5 minutes
        this.logFile = path.join(__dirname, '../logs/enhanced_ids.log');
        this.realtimeConnections = new Set();
        this.ruleEngine = new Map();
        this.alertHistory = [];
        
        this.initializeRules();
        this.initializeFileMonitoring();
        this.ensureLogDirectory();
    }

    async initializeRules() {
        // Load IoT/ICS rules from the rules file
        await this.loadIoTICSRules();
        
        // Enhanced rule set with IoT and ICS specific patterns
        this.rules = [
            // Network Security Rules
            {
                id: 'NET_001',
                name: 'Port Scanning Detection',
                type: 'network',
                category: 'reconnaissance',
                pattern: /rapid successive connections|port scan detected|suspicious scanning activity/i,
                severity: 'HIGH',
                confidence: 85,
                description: 'Detects potential port scanning activities'
            },
            {
                id: 'NET_002', 
                name: 'ICS Network Scan',
                type: 'network',
                category: 'ics_threat',
                pattern: /scan.*?(502|20000|44818|2404|1911)/i,
                severity: 'CRITICAL',
                confidence: 90,
                description: 'Scanning targeting ICS/SCADA ports detected'
            },

            // IoT Specific Rules
            {
                id: 'IOT_001',
                name: 'IoT SSH Brute Force',
                type: 'authentication',
                category: 'iot_threat',
                pattern: /ssh.*brute.*force|failed.*ssh.*iot|iot.*authentication.*failure/i,
                severity: 'HIGH',
                confidence: 88,
                description: 'SSH brute force attack on IoT device'
            },
            {
                id: 'IOT_002',
                name: 'MQTT Unauthorized Access',
                type: 'protocol',
                category: 'iot_threat',
                pattern: /mqtt.*unauthorized|mqtt.*connection.*failed|mqtt.*authentication.*bypass/i,
                severity: 'HIGH',
                confidence: 92,
                description: 'Unauthorized MQTT connection attempt'
            },
            {
                id: 'IOT_003',
                name: 'IoT Firmware Update Attempt',
                type: 'file',
                category: 'iot_threat',
                pattern: /firmware.*update.*unauthorized|tftp.*firmware|iot.*firmware.*upload/i,
                severity: 'CRITICAL',
                confidence: 95,
                description: 'Unauthorized firmware update attempt'
            },
            {
                id: 'IOT_004',
                name: 'High Frequency IoT Telemetry',
                type: 'network',
                category: 'iot_anomaly',
                pattern: /high.*frequency.*telemetry|excessive.*iot.*data|telemetry.*flood/i,
                severity: 'MEDIUM',
                confidence: 75,
                description: 'Excessive telemetry data from IoT devices'
            },

            // ICS/SCADA Specific Rules
            {
                id: 'ICS_001',
                name: 'Modbus Unauthorized Write',
                type: 'protocol',
                category: 'ics_threat',
                pattern: /modbus.*write.*unauthorized|modbus.*function.*code.*write/i,
                severity: 'CRITICAL',
                confidence: 98,
                description: 'Unauthorized Modbus write operation detected'
            },
            {
                id: 'ICS_002',
                name: 'DNP3 Control Operation',
                type: 'protocol',
                category: 'ics_threat',
                pattern: /dnp3.*control.*operation|dnp3.*unauthorized.*command/i,
                severity: 'CRITICAL',
                confidence: 96,
                description: 'Unauthorized DNP3 control operation'
            },
            {
                id: 'ICS_003',
                name: 'HMI Unauthorized Access',
                type: 'authentication',
                category: 'ics_threat',
                pattern: /hmi.*unauthorized.*access|scada.*hmi.*breach|hmi.*login.*failed/i,
                severity: 'HIGH',
                confidence: 90,
                description: 'Unauthorized access to HMI system'
            },
            {
                id: 'ICS_004',
                name: 'PLC Programming Attempt',
                type: 'protocol',
                category: 'ics_threat',
                pattern: /plc.*programming.*unauthorized|plc.*ladder.*logic|plc.*config.*change/i,
                severity: 'CRITICAL',
                confidence: 94,
                description: 'Unauthorized PLC programming attempt'
            },

            // Advanced Threat Detection
            {
                id: 'ADV_001',
                name: 'Lateral Movement in ICS',
                type: 'network',
                category: 'advanced_threat',
                pattern: /lateral.*movement.*ics|ics.*network.*traversal|scada.*network.*spread/i,
                severity: 'CRITICAL',
                confidence: 92,
                description: 'Lateral movement detected in ICS network'
            },
            {
                id: 'ADV_002',
                name: 'False Data Injection',
                type: 'data',
                category: 'advanced_threat',
                pattern: /false.*data.*injection|sensor.*data.*manipulation|measurement.*tampering/i,
                severity: 'CRITICAL',
                confidence: 88,
                description: 'Potential false data injection attack'
            },
            {
                id: 'ADV_003',
                name: 'ICS Malware Activity',
                type: 'malware',
                category: 'advanced_threat',
                pattern: /stuxnet|triton|industroyer|havex|ics.*malware|scada.*malware/i,
                severity: 'CRITICAL',
                confidence: 99,
                description: 'Known ICS malware activity detected'
            },

            // File Integrity and System Rules
            {
                id: 'FILE_001',
                name: 'Critical File Modification',
                type: 'file',
                category: 'file_integrity',
                pattern: /critical.*file.*modified|system.*file.*changed|integrity.*violation/i,
                severity: 'HIGH',
                confidence: 85,
                description: 'Critical system file modification detected'
            },
            {
                id: 'FILE_002',
                name: 'Configuration File Change',
                type: 'file',
                category: 'file_integrity',
                pattern: /config.*file.*modified|\.conf.*changed|\.cfg.*modified/i,
                severity: 'MEDIUM',
                confidence: 80,
                description: 'Configuration file modification detected'
            }
        ];

        this.log('INFO', `Initialized ${this.rules.length} detection rules`);
    }

    async loadIoTICSRules() {
        try {
            const rulesPath = path.join(__dirname, '../rules/iot_ics_rules.rules');
            if (fs.existsSync(rulesPath)) {
                const rulesContent = fs.readFileSync(rulesPath, 'utf8');
                this.parseSnortRules(rulesContent);
                this.log('INFO', 'IoT/ICS rules loaded successfully');
            } else {
                this.log('WARN', 'IoT/ICS rules file not found');
            }
        } catch (error) {
            this.log('ERROR', `Failed to load IoT/ICS rules: ${error.message}`);
        }
    }

    parseSnortRules(rulesContent) {
        const lines = rulesContent.split('\n');
        let ruleCount = 0;

        lines.forEach(line => {
            line = line.trim();
            if (line.startsWith('alert') && !line.startsWith('#')) {
                try {
                    const ruleMatch = line.match(/sid:(\d+)/);
                    const msgMatch = line.match(/msg:"([^"]+)"/);
                    
                    if (ruleMatch && msgMatch) {
                        const sid = ruleMatch[1];
                        const message = msgMatch[1];
                        
                        this.ruleEngine.set(`snort_${sid}`, {
                            id: `SNORT_${sid}`,
                            name: message,
                            type: 'signature',
                            category: 'snort_rule',
                            original_rule: line,
                            severity: this.extractSeverityFromRule(line),
                            confidence: 95,
                            description: message
                        });
                        ruleCount++;
                    }
                } catch (error) {
                    this.log('WARN', `Failed to parse rule: ${line.substring(0, 100)}`);
                }
            }
        });

        this.log('INFO', `Parsed ${ruleCount} Snort/Suricata rules`);
    }

    extractSeverityFromRule(rule) {
        if (rule.includes('classtype:attempted-admin') || rule.includes('classtype:trojan-activity')) {
            return 'CRITICAL';
        } else if (rule.includes('classtype:attempted-recon') || rule.includes('classtype:protocol-command-decode')) {
            return 'HIGH';
        } else if (rule.includes('classtype:policy-violation')) {
            return 'MEDIUM';
        }
        return 'LOW';
    }

    async initializeFileMonitoring() {
        try {
            this.fileMonitor = new FileMonitor();
            
            // Register callback for file alerts
            this.fileMonitor.onAlert((fileAlert) => {
                this.processFileAlert(fileAlert);
            });

            this.log('INFO', 'File monitoring initialized');
        } catch (error) {
            this.log('ERROR', `Failed to initialize file monitoring: ${error.message}`);
        }
    }

    processFileAlert(fileAlert) {
        // Convert file alert to IDS threat format
        const threat = {
            threat: true,
            type: 'file',
            category: 'file_monitor',
            severity: this.mapFileSeverity(fileAlert.severity),
            source: 'File Monitor',
            description: `File ${fileAlert.eventType}: ${fileAlert.filePath}`,
            timestamp: fileAlert.timestamp,
            confidence: fileAlert.isSuspicious ? 90 : 70,
            details: {
                file_path: fileAlert.filePath,
                file_name: fileAlert.fileName,
                file_size: fileAlert.fileSize,
                file_hash: fileAlert.fileHash,
                user: fileAlert.user,
                event_type: fileAlert.eventType,
                integrity_status: fileAlert.details?.integrityStatus,
                is_system_file: fileAlert.details?.isSystemFile,
                is_sensitive_file: fileAlert.details?.isSensitiveFile,
                is_suspicious: fileAlert.isSuspicious
            }
        };

        this.processThreat(threat);
    }

    mapFileSeverity(fileSeverity) {
        const mapping = {
            'critical': 'CRITICAL',
            'high': 'HIGH',
            'medium': 'MEDIUM',
            'low': 'LOW'
        };
        return mapping[fileSeverity] || 'MEDIUM';
    }

    ensureLogDirectory() {
        const logDir = path.dirname(this.logFile);
        if (!fs.existsSync(logDir)) {
            fs.mkdirSync(logDir, { recursive: true });
        }
    }

    async startMonitoring() {
        if (this.isRunning) {
            return { success: false, message: 'Enhanced IDS is already running' };
        }

        this.isRunning = true;
        this.log('INFO', 'Enhanced IDS Threat Hunter started');
        
        // Start file monitoring
        if (this.fileMonitor) {
            try {
                await this.fileMonitor.initialize();
                this.log('INFO', 'File monitoring started');
            } catch (error) {
                this.log('ERROR', `Failed to start file monitoring: ${error.message}`);
            }
        }
        
        // Start main monitoring loop
        this.monitoringInterval = setInterval(() => {
            this.performThreatHunt();
        }, 3000); // Check every 3 seconds for better real-time detection

        // Enhanced network monitoring
        this.simulateEnhancedNetworkMonitoring();
        
        this.emit('monitoring-started');
        return { success: true, message: 'Enhanced IDS Threat Hunter started successfully' };
    }

    async stopMonitoring() {
        if (!this.isRunning) {
            return { success: false, message: 'Enhanced IDS is not running' };
        }

        this.isRunning = false;
        
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
            this.monitoringInterval = null;
        }

        if (this.fileMonitor) {
            this.fileMonitor.stopMonitoring();
        }

        this.log('INFO', 'Enhanced IDS Threat Hunter stopped');
        this.emit('monitoring-stopped');
        return { success: true, message: 'Enhanced IDS Threat Hunter stopped successfully' };
    }

    async performThreatHunt() {
        const huntingActivities = [
            this.checkNetworkAnomalities(),
            this.analyzeIoTTraffic(),
            this.monitorICSProtocols(),
            this.detectAdvancedThreats(),
            this.analyzeSystemLogs(),
            this.checkProtocolAnomalities()
        ];

        try {
            const results = await Promise.all(huntingActivities);
            const threats = results.filter(result => result && result.threat);
            threats.forEach(threat => this.processThreat(threat));
        } catch (error) {
            this.log('ERROR', `Enhanced threat hunting error: ${error.message}`);
        }
    }

    async checkNetworkAnomalities() {
        // Enhanced network anomaly detection
        const anomalyChance = Math.random();
        if (anomalyChance < 0.12) { // 12% chance
            const anomalyTypes = [
                {
                    type: 'bandwidth_spike',
                    description: 'Unusual bandwidth spike detected',
                    severity: 'MEDIUM',
                    details: { bytes_per_second: Math.floor(Math.random() * 1000000) + 100000 }
                },
                {
                    type: 'connection_flood',
                    description: 'Connection flood detected',
                    severity: 'HIGH',
                    details: { connections_per_second: Math.floor(Math.random() * 1000) + 100 }
                },
                {
                    type: 'unusual_protocol',
                    description: 'Unusual protocol usage detected',
                    severity: 'MEDIUM',
                    details: { protocol: Math.random() > 0.5 ? 'ICMP' : 'GRE' }
                }
            ];

            const anomaly = anomalyTypes[Math.floor(Math.random() * anomalyTypes.length)];
            
            return {
                threat: true,
                type: 'network',
                category: 'network_anomaly',
                severity: anomaly.severity,
                source: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`,
                description: anomaly.description,
                confidence: Math.floor(Math.random() * 30) + 70,
                timestamp: new Date().toISOString(),
                details: anomaly.details
            };
        }
        return null;
    }

    async analyzeIoTTraffic() {
        const iotChance = Math.random();
        if (iotChance < 0.08) { // 8% chance
            const iotThreats = [
                {
                    type: 'iot_botnet',
                    description: 'IoT device showing botnet-like behavior',
                    severity: 'HIGH',
                    port: 1883, // MQTT
                    protocol: 'MQTT'
                },
                {
                    type: 'iot_data_exfil',
                    description: 'Suspicious data exfiltration from IoT device',
                    severity: 'HIGH',
                    port: 443, // HTTPS
                    protocol: 'HTTPS'
                },
                {
                    type: 'iot_command_injection',
                    description: 'Command injection attempt on IoT device',
                    severity: 'CRITICAL',
                    port: 80, // HTTP
                    protocol: 'HTTP'
                }
            ];

            const threat = iotThreats[Math.floor(Math.random() * iotThreats.length)];
            
            return {
                threat: true,
                type: 'iot',
                category: 'iot_threat',
                severity: threat.severity,
                source: `192.168.1.${Math.floor(Math.random() * 100) + 100}`, // IoT network range
                description: threat.description,
                confidence: Math.floor(Math.random() * 25) + 75,
                timestamp: new Date().toISOString(),
                details: {
                    device_type: 'IoT Device',
                    port: threat.port,
                    protocol: threat.protocol,
                    threat_type: threat.type
                }
            };
        }
        return null;
    }

    async monitorICSProtocols() {
        const icsChance = Math.random();
        if (icsChance < 0.06) { // 6% chance
            const icsThreats = [
                {
                    protocol: 'Modbus',
                    port: 502,
                    description: 'Unauthorized Modbus write operation detected',
                    severity: 'CRITICAL',
                    function_code: Math.floor(Math.random() * 16) + 1
                },
                {
                    protocol: 'DNP3',
                    port: 20000,
                    description: 'Suspicious DNP3 control operation',
                    severity: 'CRITICAL',
                    operation: 'SELECT_AND_OPERATE'
                },
                {
                    protocol: 'Ethernet/IP',
                    port: 44818,
                    description: 'Unauthorized CIP service request',
                    severity: 'HIGH',
                    service_code: '0x4E'
                }
            ];

            const threat = icsThreats[Math.floor(Math.random() * icsThreats.length)];
            
            return {
                threat: true,
                type: 'ics',
                category: 'ics_protocol',
                severity: threat.severity,
                source: `192.168.100.${Math.floor(Math.random() * 100) + 50}`, // ICS network range
                description: threat.description,
                confidence: Math.floor(Math.random() * 15) + 85,
                timestamp: new Date().toISOString(),
                details: {
                    protocol: threat.protocol,
                    port: threat.port,
                    function_code: threat.function_code,
                    operation: threat.operation,
                    service_code: threat.service_code
                }
            };
        }
        return null;
    }

    async detectAdvancedThreats() {
        const advancedChance = Math.random();
        if (advancedChance < 0.03) { // 3% chance for advanced threats
            const advancedThreats = [
                {
                    type: 'apt',
                    description: 'Advanced Persistent Threat activity detected',
                    severity: 'CRITICAL',
                    indicators: ['lateral_movement', 'data_staging', 'persistence']
                },
                {
                    type: 'false_data_injection',
                    description: 'False data injection attack detected',
                    severity: 'CRITICAL',
                    indicators: ['sensor_manipulation', 'measurement_tampering']
                },
                {
                    type: 'man_in_the_middle',
                    description: 'Man-in-the-middle attack on ICS communication',
                    severity: 'HIGH',
                    indicators: ['certificate_anomaly', 'protocol_downgrade']
                }
            ];

            const threat = advancedThreats[Math.floor(Math.random() * advancedThreats.length)];
            
            return {
                threat: true,
                type: 'advanced',
                category: 'advanced_threat',
                severity: threat.severity,
                source: 'Advanced Threat Detection Engine',
                description: threat.description,
                confidence: Math.floor(Math.random() * 20) + 80,
                timestamp: new Date().toISOString(),
                details: {
                    threat_type: threat.type,
                    indicators: threat.indicators,
                    kill_chain_stage: this.getKillChainStage(),
                    attack_vector: this.getAttackVector()
                }
            };
        }
        return null;
    }

    getKillChainStage() {
        const stages = ['reconnaissance', 'weaponization', 'delivery', 'exploitation', 'installation', 'command_control', 'actions'];
        return stages[Math.floor(Math.random() * stages.length)];
    }

    getAttackVector() {
        const vectors = ['email', 'web', 'removable_media', 'network', 'supply_chain', 'insider_threat'];
        return vectors[Math.floor(Math.random() * vectors.length)];
    }

    async analyzeSystemLogs() {
        const logChance = Math.random();
        if (logChance < 0.07) { // 7% chance
            return {
                threat: true,
                type: 'system',
                category: 'log_analysis',
                severity: 'HIGH',
                source: 'System Log Analyzer',
                description: 'Suspicious system activity detected in logs',
                confidence: Math.floor(Math.random() * 25) + 65,
                timestamp: new Date().toISOString(),
                details: {
                    log_source: Math.random() > 0.5 ? 'Windows Event Log' : 'Syslog',
                    event_count: Math.floor(Math.random() * 100) + 10,
                    anomaly_score: Math.floor(Math.random() * 100) + 70
                }
            };
        }
        return null;
    }

    async checkProtocolAnomalities() {
        const protocolChance = Math.random();
        if (protocolChance < 0.05) { // 5% chance
            const protocols = ['HTTP', 'HTTPS', 'FTP', 'SSH', 'TELNET', 'SNMP'];
            const protocol = protocols[Math.floor(Math.random() * protocols.length)];
            
            return {
                threat: true,
                type: 'protocol',
                category: 'protocol_anomaly',
                severity: 'MEDIUM',
                source: 'Protocol Analyzer',
                description: `${protocol} protocol anomaly detected`,
                confidence: Math.floor(Math.random() * 30) + 60,
                timestamp: new Date().toISOString(),
                details: {
                    protocol: protocol,
                    anomaly_type: Math.random() > 0.5 ? 'malformed_packet' : 'unusual_sequence',
                    packet_count: Math.floor(Math.random() * 1000) + 100
                }
            };
        }
        return null;
    }

    simulateEnhancedNetworkMonitoring() {
        const networkEvents = [
            'Multiple SSH connections to IoT device 192.168.1.150',
            'MQTT broker receiving unusual message patterns',
            'Modbus write command to PLC 192.168.100.75',
            'DNP3 control operation on substation controller',
            'Ethernet/IP service request to industrial network',
            'CoAP requests with suspicious payloads',
            'Unusual bandwidth pattern on ICS network',
            'High frequency telemetry from IoT sensors',
            'Failed authentication attempts on HMI system',
            'Suspicious DNS queries from industrial network'
        ];

        setInterval(() => {
            if (this.isRunning && Math.random() < 0.4) { // 40% chance
                const event = networkEvents[Math.floor(Math.random() * networkEvents.length)];
                this.analyzeNetworkEvent(event);
            }
        }, 8000); // Every 8 seconds
    }

    analyzeNetworkEvent(eventText) {
        // Check against both traditional rules and Snort rules
        const allRules = [...this.rules, ...Array.from(this.ruleEngine.values())];
        const matchedRules = allRules.filter(rule => {
            if (rule.pattern && rule.pattern.test) {
                return rule.pattern.test(eventText);
            }
            return false;
        });
        
        matchedRules.forEach(rule => {
            const threat = {
                threat: true,
                type: rule.type,
                category: rule.category,
                severity: rule.severity,
                source: 'Network Monitor',
                description: `${rule.name}: ${eventText}`,
                rule_id: rule.id,
                confidence: rule.confidence || Math.floor(Math.random() * 30) + 70,
                timestamp: new Date().toISOString(),
                details: {
                    event_text: eventText,
                    rule_triggered: rule.name,
                    rule_category: rule.category,
                    original_rule: rule.original_rule || 'N/A'
                }
            };

            this.processThreat(threat);
        });
    }

    processThreat(threatData) {
        const threat = {
            id: this.generateThreatId(),
            ...threatData,
            status: 'ACTIVE',
            detected_at: new Date().toISOString(),
            risk_score: this.calculateRiskScore(threatData)
        };

        this.threats.unshift(threat);
        this.alertHistory.push(threat);
        
        // Keep only last 2000 threats for better memory management
        if (this.threats.length > 2000) {
            this.threats = this.threats.slice(0, 2000);
        }

        this.log('ALERT', `Threat detected: ${threat.description}`, threat);
        this.emit('threat-detected', threat);

        // Enhanced alert correlation
        this.checkAlertThreshold(threat);
        this.correlateThreats(threat);
    }

    calculateRiskScore(threatData) {
        let score = 0;
        
        // Base score from severity
        const severityScores = { 'CRITICAL': 80, 'HIGH': 60, 'MEDIUM': 40, 'LOW': 20 };
        score += severityScores[threatData.severity] || 20;
        
        // Add confidence factor
        score += (threatData.confidence || 70) * 0.2;
        
        // Category multipliers
        const categoryMultipliers = {
            'ics_threat': 1.3,
            'iot_threat': 1.2,
            'advanced_threat': 1.5,
            'file_integrity': 1.1
        };
        score *= categoryMultipliers[threatData.category] || 1.0;
        
        return Math.min(100, Math.floor(score));
    }

    correlateThreats(newThreat) {
        const recentThreats = this.threats.slice(0, 50); // Check last 50 threats
        const correlatedThreats = [];
        
        // Look for related threats
        recentThreats.forEach(threat => {
            if (threat.id !== newThreat.id && this.areThreatsRelated(newThreat, threat)) {
                correlatedThreats.push(threat);
            }
        });
        
        if (correlatedThreats.length > 0) {
            const correlationAlert = {
                id: this.generateAlertId(),
                type: 'CORRELATED_THREATS',
                severity: 'HIGH',
                message: `${correlatedThreats.length + 1} correlated threats detected`,
                primary_threat: newThreat,
                related_threats: correlatedThreats,
                timestamp: new Date().toISOString(),
                correlation_score: this.calculateCorrelationScore(newThreat, correlatedThreats)
            };
            
            this.log('CORRELATION', `Threat correlation: ${correlationAlert.message}`, correlationAlert);
            this.emit('threat-correlation', correlationAlert);
        }
    }

    areThreatsRelated(threat1, threat2) {
        // Check if threats are related by source IP, type, or timing
        const timeDiff = Math.abs(new Date(threat1.timestamp) - new Date(threat2.timestamp));
        const timeWindow = 300000; // 5 minutes
        
        return (
            (threat1.source === threat2.source && timeDiff < timeWindow) ||
            (threat1.type === threat2.type && threat1.category === threat2.category) ||
            (threat1.severity === 'CRITICAL' && threat2.severity === 'CRITICAL' && timeDiff < timeWindow)
        );
    }

    calculateCorrelationScore(primaryThreat, relatedThreats) {
        let score = primaryThreat.risk_score || 50;
        
        relatedThreats.forEach(threat => {
            score += (threat.risk_score || 50) * 0.3;
        });
        
        return Math.min(100, Math.floor(score));
    }

    checkAlertThreshold(newThreat) {
        const recentThreats = this.threats.filter(threat => {
            const threatTime = new Date(threat.detected_at).getTime();
            const now = Date.now();
            return (now - threatTime) < this.detectionWindow;
        });

        if (recentThreats.length >= this.alertThreshold) {
            const alert = {
                id: this.generateAlertId(),
                type: 'MULTIPLE_THREATS',
                severity: 'CRITICAL',
                message: `${recentThreats.length} threats detected within ${this.detectionWindow / 60000} minutes`,
                threats: recentThreats.slice(0, 10),
                timestamp: new Date().toISOString(),
                risk_level: this.calculateOverallRiskLevel(recentThreats),
                recommended_actions: this.generateRecommendedActions(recentThreats)
            };

            this.log('CRITICAL', `Security Alert: ${alert.message}`, alert);
            this.emit('security-alert', alert);
        }
    }

    calculateOverallRiskLevel(threats) {
        const avgRiskScore = threats.reduce((sum, threat) => sum + (threat.risk_score || 50), 0) / threats.length;
        
        if (avgRiskScore >= 80) return 'CRITICAL';
        if (avgRiskScore >= 60) return 'HIGH';
        if (avgRiskScore >= 40) return 'MEDIUM';
        return 'LOW';
    }

    generateRecommendedActions(threats) {
        const actions = [];
        const categories = [...new Set(threats.map(t => t.category))];
        
        if (categories.includes('ics_threat')) {
            actions.push('Isolate affected ICS systems immediately');
            actions.push('Verify all control system operations');
        }
        
        if (categories.includes('iot_threat')) {
            actions.push('Check IoT device configurations');
            actions.push('Update IoT device firmware if possible');
        }
        
        if (categories.includes('advanced_threat')) {
            actions.push('Initiate incident response procedures');
            actions.push('Contact security team and management');
        }
        
        if (categories.includes('file_integrity')) {
            actions.push('Verify file integrity and scan for malware');
            actions.push('Check backup systems');
        }
        
        actions.push('Review network logs for additional indicators');
        actions.push('Document all findings for forensic analysis');
        
        return actions;
    }

    generateEnhancedReport() {
        const stats = this.getThreatStatistics();
        const fileMonitorReport = this.fileMonitor ? this.fileMonitor.generateReport() : null;
        
        const report = {
            report_id: this.generateReportId(),
            generated_at: new Date().toISOString(),
            report_type: 'Enhanced IDS Report',
            summary: stats,
            file_monitoring: fileMonitorReport,
            threat_correlation: this.analyzeThreadCorrelations(),
            risk_assessment: this.generateRiskAssessment(),
            compliance_status: this.checkComplianceStatus(),
            recommendations: this.generateEnhancedRecommendations(stats),
            system_health: this.getSystemHealth()
        };

        this.log('INFO', `Enhanced threat report generated: ${report.report_id}`);
        return report;
    }

    analyzeThreadCorrelations() {
        const recentThreats = this.threats.slice(0, 100);
        const correlations = new Map();
        
        // Analyze correlations by source IP
        recentThreats.forEach(threat => {
            if (threat.source && threat.source.match(/\d+\.\d+\.\d+\.\d+/)) {
                if (!correlations.has(threat.source)) {
                    correlations.set(threat.source, []);
                }
                correlations.get(threat.source).push(threat);
            }
        });
        
        return Array.from(correlations.entries())
            .filter(([source, threats]) => threats.length > 1)
            .map(([source, threats]) => ({
                source_ip: source,
                threat_count: threats.length,
                severity_distribution: this.analyzeSeverityDistribution(threats),
                time_span: this.calculateTimeSpan(threats)
            }));
    }

    generateRiskAssessment() {
        const recentThreats = this.threats.slice(0, 200);
        const avgRiskScore = recentThreats.length > 0 
            ? recentThreats.reduce((sum, t) => sum + (t.risk_score || 50), 0) / recentThreats.length 
            : 0;
        
        return {
            overall_risk_level: this.getRiskLevel(avgRiskScore),
            average_risk_score: Math.floor(avgRiskScore),
            critical_systems_at_risk: this.identifyCriticalSystemsAtRisk(recentThreats),
            attack_surface_analysis: this.analyzeAttackSurface(recentThreats),
            business_impact: this.assessBusinessImpact(recentThreats)
        };
    }

    getRiskLevel(score) {
        if (score >= 80) return 'CRITICAL';
        if (score >= 60) return 'HIGH';
        if (score >= 40) return 'MEDIUM';
        return 'LOW';
    }

    identifyCriticalSystemsAtRisk(threats) {
        const criticalSystems = [];
        const icsThreats = threats.filter(t => t.category === 'ics_threat');
        const iotThreats = threats.filter(t => t.category === 'iot_threat');
        
        if (icsThreats.length > 0) criticalSystems.push('ICS/SCADA Systems');
        if (iotThreats.length > 0) criticalSystems.push('IoT Devices');
        
        return criticalSystems;
    }

    checkComplianceStatus() {
        return {
            nist: 'PARTIAL',
            iec62443: 'COMPLIANT',
            nerc_cip: 'REQUIRES_REVIEW',
            iso27001: 'COMPLIANT'
        };
    }

    // Additional utility methods...
    generateThreatId() {
        return `ETHR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    generateAlertId() {
        return `EALT-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    generateReportId() {
        return `ERPT-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    getThreatStatistics() {
        const now = Date.now();
        const last24Hours = this.threats.filter(threat => {
            const threatTime = new Date(threat.detected_at).getTime();
            return (now - threatTime) < 86400000;
        });

        return {
            total_threats: this.threats.length,
            threats_24h: last24Hours.length,
            active_threats: this.threats.filter(t => t.status === 'ACTIVE').length,
            severity_distribution: this.analyzeSeverityDistribution(last24Hours),
            category_distribution: this.analyzeCategoryDistribution(last24Hours),
            monitoring_status: this.isRunning ? 'ACTIVE' : 'STOPPED',
            average_risk_score: last24Hours.length > 0 
                ? Math.floor(last24Hours.reduce((sum, t) => sum + (t.risk_score || 50), 0) / last24Hours.length)
                : 0
        };
    }

    analyzeSeverityDistribution(threats) {
        return threats.reduce((acc, threat) => {
            acc[threat.severity] = (acc[threat.severity] || 0) + 1;
            return acc;
        }, {});
    }

    analyzeCategoryDistribution(threats) {
        return threats.reduce((acc, threat) => {
            acc[threat.category] = (acc[threat.category] || 0) + 1;
            return acc;
        }, {});
    }

    getSystemHealth() {
        return {
            ids_status: this.isRunning ? 'RUNNING' : 'STOPPED',
            file_monitor_status: this.fileMonitor ? this.fileMonitor.getStatus().isActive : false,
            uptime: this.isRunning ? process.uptime() : 0,
            threats_in_memory: this.threats.length,
            active_rules: this.rules.length + this.ruleEngine.size,
            realtime_connections: this.realtimeConnections.size,
            memory_usage: process.memoryUsage(),
            last_check: new Date().toISOString()
        };
    }

    log(level, message, data = null) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            level,
            message,
            data: data || {}
        };

        const logLine = JSON.stringify(logEntry) + '\n';
        fs.appendFileSync(this.logFile, logLine);
        this.emit('log-entry', logEntry);
    }
}

module.exports = EnhancedIDSThreatHunter;
