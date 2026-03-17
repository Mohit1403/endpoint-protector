const fs = require('fs');
const path = require('path');
const chokidar = require('chokidar');
const { EventEmitter } = require('events');
const os = require('os');

class IDSThreatHunter extends EventEmitter {
    constructor() {
        super();
        this.isRunning = false;
        this.threats = [];
        this.rules = [];
        this.monitoringInterval = null;
        this.alertThreshold = 3; // Number of suspicious activities before alert
        this.detectionWindow = 300000; // 5 minutes in milliseconds
        this.logFile = path.join(__dirname, '../logs/ids.log');
        this.realtimeConnections = new Set();
        
        // File system monitoring
        this.fileWatchers = [];
        this.monitoredPaths = [];
        this.fileSystemEnabled = false;
        this.currentUser = os.userInfo().username;
        
        this.initializeRules();
        this.ensureLogDirectory();
    }

    initializeRules() {
        // Comprehensive IDS Rules Database
        this.rules = [
            // ===== ORIGINAL BASIC RULES =====
            {
                id: 'SUSPICIOUS_PORT_SCAN',
                name: 'Port Scanning Detection',
                type: 'network',
                pattern: /rapid successive connections|port scan detected|suspicious scanning activity/i,
                severity: 'HIGH',
                description: 'Detects potential port scanning activities',
                category: 'network_reconnaissance'
            },
            {
                id: 'BRUTE_FORCE_ATTEMPT',
                name: 'Brute Force Attack Detection',
                type: 'authentication',
                pattern: /failed login attempt|authentication failure|multiple login failures/i,
                severity: 'CRITICAL',
                description: 'Detects brute force authentication attempts',
                category: 'authentication_attacks'
            },
            {
                id: 'MALWARE_SIGNATURE',
                name: 'Malware Signature Detection',
                type: 'malware',
                pattern: /trojan|virus|malware|backdoor|rootkit/i,
                severity: 'CRITICAL',
                description: 'Detects known malware signatures',
                category: 'malware_detection'
            },
            {
                id: 'SUSPICIOUS_NETWORK_TRAFFIC',
                name: 'Anomalous Network Traffic',
                type: 'network',
                pattern: /unusual traffic pattern|bandwidth spike|connection anomaly/i,
                severity: 'MEDIUM',
                description: 'Detects unusual network traffic patterns',
                category: 'network_anomaly'
            },
            {
                id: 'FILE_INTEGRITY_VIOLATION',
                name: 'File Integrity Check',
                type: 'file',
                pattern: /file modified|unauthorized access|integrity violation/i,
                severity: 'HIGH',
                description: 'Detects unauthorized file modifications',
                category: 'file_integrity'
            },
            {
                id: 'PRIVILEGE_ESCALATION',
                name: 'Privilege Escalation Attempt',
                type: 'system',
                pattern: /privilege escalation|unauthorized admin access|elevation attempt/i,
                severity: 'CRITICAL',
                description: 'Detects privilege escalation attempts',
                category: 'system_compromise'
            },
            {
                id: 'SQL_INJECTION',
                name: 'SQL Injection Detection',
                type: 'web',
                pattern: /union select|drop table|sql injection|malicious query/i,
                severity: 'HIGH',
                description: 'Detects SQL injection attempts',
                category: 'web_attacks'
            },
            {
                id: 'XSS_ATTACK',
                name: 'Cross-Site Scripting Detection',
                type: 'web',
                pattern: /<script|javascript:|xss attack|malicious script/i,
                severity: 'MEDIUM',
                description: 'Detects cross-site scripting attempts',
                category: 'web_attacks'
            },
            
            // ===== IOT THREAT DETECTION RULES =====
            {
                id: 'IOT_SSH_BRUTE_FORCE',
                name: 'IoT SSH Brute Force Attack',
                type: 'iot_authentication',
                pattern: /SSH.*brute.*force|multiple.*SSH.*failed|SSH.*attack.*detected/i,
                severity: 'CRITICAL',
                description: 'Detects SSH brute force attacks on IoT devices',
                category: 'iot_security'
            },
            {
                id: 'IOT_TELNET_BRUTE_FORCE',
                name: 'IoT Telnet Brute Force Attack',
                type: 'iot_authentication',
                pattern: /telnet.*brute.*force|telnet.*login.*failed|multiple.*telnet.*attempts/i,
                severity: 'HIGH',
                description: 'Detects Telnet brute force on IoT devices',
                category: 'iot_security'
            },
            {
                id: 'IOT_HTTP_AUTH_BRUTE_FORCE',
                name: 'IoT HTTP Authentication Attack',
                type: 'iot_web',
                pattern: /HTTP.*basic.*auth.*brute|web.*interface.*brute|IoT.*login.*attack/i,
                severity: 'HIGH',
                description: 'Detects HTTP authentication attacks on IoT web interfaces',
                category: 'iot_security'
            },
            {
                id: 'DNS_TUNNELING',
                name: 'DNS Tunneling Detection',
                type: 'network_covert',
                pattern: /DNS.*tunneling|suspicious.*DNS.*query|long.*DNS.*request/i,
                severity: 'HIGH',
                description: 'Detects potential DNS tunneling for C2 communications',
                category: 'covert_channels'
            },
            {
                id: 'IOT_FIRMWARE_UPDATE',
                name: 'Unauthorized IoT Firmware Update',
                type: 'iot_management',
                pattern: /firmware.*update|TFTP.*upload|unauthorized.*firmware|IoT.*update.*attempt/i,
                severity: 'CRITICAL',
                description: 'Detects unauthorized firmware update attempts',
                category: 'iot_security'
            },
            {
                id: 'IOT_HIGH_FREQ_TELEMETRY',
                name: 'High-Frequency IoT Telemetry',
                type: 'iot_data',
                pattern: /high.*frequency.*telemetry|excessive.*IoT.*data|abnormal.*data.*transmission/i,
                severity: 'MEDIUM',
                description: 'Detects excessive data transmission from IoT devices',
                category: 'data_exfiltration'
            },
            {
                id: 'MQTT_UNAUTHORIZED_ACCESS',
                name: 'MQTT Unauthorized Access',
                type: 'iot_protocol',
                pattern: /MQTT.*unauthorized|MQTT.*connection.*failed|MQTT.*access.*denied/i,
                severity: 'HIGH',
                description: 'Detects unauthorized MQTT access attempts',
                category: 'iot_security'
            },
            {
                id: 'COAP_UNAUTHORIZED_ACCESS',
                name: 'CoAP Unauthorized Access',
                type: 'iot_protocol',
                pattern: /CoAP.*unauthorized|CoAP.*access.*attempt|CoAP.*security.*violation/i,
                severity: 'HIGH',
                description: 'Detects unauthorized CoAP access attempts',
                category: 'iot_security'
            },
            
            // ===== ICS/SCADA THREAT DETECTION RULES =====
            {
                id: 'MODBUS_UNAUTHORIZED_WRITE',
                name: 'Modbus Unauthorized Write Command',
                type: 'ics_protocol',
                pattern: /Modbus.*write.*command|Modbus.*unauthorized.*write|Modbus.*function.*code.*write/i,
                severity: 'CRITICAL',
                description: 'Detects unauthorized Modbus write operations',
                category: 'ics_security'
            },
            {
                id: 'MODBUS_EXCEPTION_RESPONSE',
                name: 'Modbus Exception Response',
                type: 'ics_protocol',
                pattern: /Modbus.*exception|Modbus.*error.*response|Modbus.*attack.*detected/i,
                severity: 'HIGH',
                description: 'Detects Modbus exception responses indicating potential attacks',
                category: 'ics_security'
            },
            {
                id: 'DNP3_UNAUTHORIZED_CONTROL',
                name: 'DNP3 Unauthorized Control Operation',
                type: 'ics_protocol',
                pattern: /DNP3.*control.*operation|DNP3.*unauthorized.*command|DNP3.*security.*violation/i,
                severity: 'CRITICAL',
                description: 'Detects unauthorized DNP3 control operations',
                category: 'ics_security'
            },
            {
                id: 'DNP3_AUTH_BYPASS',
                name: 'DNP3 Authentication Bypass',
                type: 'ics_protocol',
                pattern: /DNP3.*authentication.*bypass|DNP3.*auth.*failure|DNP3.*security.*bypass/i,
                severity: 'CRITICAL',
                description: 'Detects DNP3 authentication bypass attempts',
                category: 'ics_security'
            },
            {
                id: 'ETHERNET_IP_UNAUTHORIZED',
                name: 'Ethernet/IP Unauthorized Service Request',
                type: 'ics_protocol',
                pattern: /Ethernet\/IP.*unauthorized|CIP.*service.*request|EtherNet\/IP.*violation/i,
                severity: 'HIGH',
                description: 'Detects unauthorized Ethernet/IP service requests',
                category: 'ics_security'
            },
            {
                id: 'ICS_NETWORK_SCAN',
                name: 'ICS Network Scanning',
                type: 'ics_reconnaissance',
                pattern: /ICS.*network.*scan|SCADA.*port.*scan|industrial.*system.*scan/i,
                severity: 'HIGH',
                description: 'Detects network scanning targeting ICS systems',
                category: 'network_reconnaissance'
            },
            {
                id: 'SCADA_HMI_UNAUTHORIZED',
                name: 'SCADA HMI Unauthorized Access',
                type: 'ics_access',
                pattern: /SCADA.*HMI.*access|HMI.*unauthorized|SCADA.*interface.*breach/i,
                severity: 'CRITICAL',
                description: 'Detects unauthorized access to SCADA HMI systems',
                category: 'ics_security'
            },
            {
                id: 'PLC_PROGRAMMING_ATTEMPT',
                name: 'Unauthorized PLC Programming',
                type: 'ics_programming',
                pattern: /PLC.*programming|PLC.*configuration.*change|unauthorized.*PLC.*access/i,
                severity: 'CRITICAL',
                description: 'Detects unauthorized PLC programming attempts',
                category: 'ics_security'
            },
            {
                id: 'MODBUS_STATE_VIOLATION',
                name: 'Modbus Protocol State Violation',
                type: 'ics_protocol',
                pattern: /Modbus.*state.*violation|Modbus.*protocol.*anomaly|Modbus.*sequence.*error/i,
                severity: 'HIGH',
                description: 'Detects Modbus protocol state violations',
                category: 'protocol_anomaly'
            },
            {
                id: 'ICS_TIME_SYNC_ATTACK',
                name: 'Industrial Time Synchronization Attack',
                type: 'ics_timing',
                pattern: /time.*sync.*attack|PTP.*manipulation|time.*synchronization.*anomaly/i,
                severity: 'MEDIUM',
                description: 'Detects attacks on industrial time synchronization protocols',
                category: 'ics_security'
            },
            
            // ===== ADVANCED THREAT DETECTION =====
            {
                id: 'FALSE_DATA_INJECTION',
                name: 'False Data Injection Attack',
                type: 'data_integrity',
                pattern: /false.*data.*injection|sensor.*data.*anomaly|data.*manipulation.*attack/i,
                severity: 'CRITICAL',
                description: 'Detects false data injection attacks on sensor data',
                category: 'data_integrity'
            },
            {
                id: 'REPLAY_ATTACK',
                name: 'Replay Attack Detection',
                type: 'protocol_attack',
                pattern: /replay.*attack|command.*repetition|duplicate.*message.*attack/i,
                severity: 'HIGH',
                description: 'Detects replay attacks on industrial commands',
                category: 'protocol_attacks'
            },
            {
                id: 'ICS_LATERAL_MOVEMENT',
                name: 'Lateral Movement in Industrial Network',
                type: 'network_movement',
                pattern: /lateral.*movement|ICS.*network.*traversal|industrial.*network.*compromise/i,
                severity: 'CRITICAL',
                description: 'Detects lateral movement in industrial networks',
                category: 'network_compromise'
            },
            {
                id: 'ICS_SUSPICIOUS_OUTBOUND',
                name: 'Suspicious Outbound from ICS Network',
                type: 'network_policy',
                pattern: /suspicious.*outbound|ICS.*external.*communication|unauthorized.*network.*access/i,
                severity: 'HIGH',
                description: 'Detects suspicious outbound communications from ICS networks',
                category: 'policy_violation'
            },
            {
                id: 'ICS_MALWARE_C2',
                name: 'ICS Malware C2 Communication',
                type: 'malware_c2',
                pattern: /ICS.*malware.*C2|command.*control.*communication|malware.*beacon/i,
                severity: 'CRITICAL',
                description: 'Detects malware C2 communication patterns in ICS networks',
                category: 'malware_detection'
            },
            
            // ===== PROTOCOL ANOMALY DETECTION =====
            {
                id: 'MODBUS_LENGTH_MANIPULATION',
                name: 'Modbus Length Field Manipulation',
                type: 'protocol_anomaly',
                pattern: /Modbus.*length.*manipulation|Modbus.*field.*anomaly|Modbus.*packet.*malformed/i,
                severity: 'HIGH',
                description: 'Detects Modbus length field manipulation',
                category: 'protocol_anomaly'
            },
            {
                id: 'DNP3_FRAGMENT_FLOOD',
                name: 'DNP3 Fragment Flood Attack',
                type: 'protocol_dos',
                pattern: /DNP3.*fragment.*flood|DNP3.*fragmentation.*attack|DNP3.*packet.*flood/i,
                severity: 'HIGH',
                description: 'Detects DNP3 fragment flood attacks',
                category: 'denial_of_service'
            },
            {
                id: 'ETHERNET_IP_CONNECTION_EXHAUSTION',
                name: 'Ethernet/IP Connection Exhaustion',
                type: 'protocol_dos',
                pattern: /Ethernet\/IP.*connection.*exhaustion|EIP.*connection.*flood|CIP.*connection.*attack/i,
                severity: 'HIGH',
                description: 'Detects Ethernet/IP connection exhaustion attacks',
                category: 'denial_of_service'
            },
            
            // ===== FILE SYSTEM MONITORING RULES =====
            {
                id: 'CRITICAL_SYSTEM_FILE_MODIFIED',
                name: 'Critical System File Modified',
                type: 'file_system',
                pattern: /critical.*system.*file.*modified|system.*file.*change|kernel.*file.*modified/i,
                severity: 'CRITICAL',
                description: 'Detects modifications to critical system files',
                category: 'file_integrity'
            },
            {
                id: 'CONFIGURATION_FILE_CHANGED',
                name: 'Configuration File Changed',
                type: 'file_system',
                pattern: /configuration.*file.*modified|config.*file.*change|\.conf.*modified|\.ini.*modified/i,
                severity: 'MEDIUM',
                description: 'Detects changes to configuration files',
                category: 'file_integrity'
            },
            {
                id: 'SENSITIVE_FILE_ACCESS',
                name: 'Sensitive File Accessed',
                type: 'file_system',
                pattern: /sensitive.*file.*accessed|password.*file.*access|key.*file.*access|cert.*file.*access/i,
                severity: 'HIGH',
                description: 'Detects access to sensitive files',
                category: 'file_access'
            },
            {
                id: 'FILE_DELETION_EVENT',
                name: 'File Deletion Detected',
                type: 'file_system',
                pattern: /file.*deletion.*detected|file.*deleted|rm.*command.*executed/i,
                severity: 'MEDIUM',
                description: 'Detects file deletion events',
                category: 'file_operations'
            },
            {
                id: 'MASS_FILE_OPERATIONS',
                name: 'Mass File Operations',
                type: 'file_system',
                pattern: /mass.*file.*operations|bulk.*file.*changes|rapid.*file.*modifications/i,
                severity: 'HIGH',
                description: 'Detects mass file operations that could indicate malware',
                category: 'malware_activity'
            },
            
            // ===== APT AND ADVANCED ATTACK DETECTION =====
            {
                id: 'APT_ENCRYPTED_C2',
                name: 'Suspicious Encrypted C2 Pattern',
                type: 'apt_c2',
                pattern: /encrypted.*C2.*pattern|suspicious.*encrypted.*traffic|APT.*communication/i,
                severity: 'CRITICAL',
                description: 'Detects potential APT C2 communication in encrypted channels',
                category: 'apt_detection'
            },
            {
                id: 'APT_DATA_STAGING',
                name: 'Data Staging Activity',
                type: 'apt_data',
                pattern: /data.*staging.*activity|large.*file.*transfer|temporary.*data.*storage/i,
                severity: 'HIGH',
                description: 'Identifies APT data staging activities',
                category: 'data_exfiltration'
            },
            {
                id: 'STUXNET_LIKE_BEHAVIOR',
                name: 'ICS Malware Process Manipulation',
                type: 'ics_malware',
                pattern: /Step7|s7otbxdx\.dll|ICS.*malware|Siemens.*exploit|PLC.*manipulation/i,
                severity: 'CRITICAL',
                description: 'Detects Stuxnet-like malware behavior targeting industrial systems',
                category: 'ics_malware'
            },
            {
                id: 'HMI_BUFFER_OVERFLOW',
                name: 'HMI Buffer Overflow Attempt',
                type: 'exploit_attempt',
                pattern: /HMI.*buffer.*overflow|HMI.*exploit.*attempt|buffer.*overflow.*HMI/i,
                severity: 'HIGH',
                description: 'Detects buffer overflow attempts against HMI software',
                category: 'exploit_attempts'
            },
            
            // ===== ANOMALY AND BEHAVIOR DETECTION =====
            {
                id: 'PROTOCOL_ANOMALY',
                name: 'Protocol Anomaly Detected',
                type: 'protocol_anomaly',
                pattern: /protocol.*anomaly|malformed.*packet|protocol.*violation/i,
                severity: 'MEDIUM',
                description: 'Detects protocol anomalies and malformed packets',
                category: 'protocol_anomaly'
            },
            {
                id: 'TIMING_ATTACK',
                name: 'Timing Attack Detection',
                type: 'cryptographic_attack',
                pattern: /timing.*attack|cryptographic.*timing|side.*channel.*attack/i,
                severity: 'HIGH',
                description: 'Detects timing attacks against cryptographic implementations',
                category: 'cryptographic_attacks'
            },
            {
                id: 'ABNORMAL_DATA_PATTERN',
                name: 'Abnormal Sensor Data Pattern',
                type: 'data_anomaly',
                pattern: /abnormal.*sensor.*data|data.*pattern.*anomaly|sensor.*value.*suspicious/i,
                severity: 'MEDIUM',
                description: 'Detects abnormal data patterns in sensor readings',
                category: 'data_integrity'
            },
            
            // ===== NETWORK RECONNAISSANCE =====
            {
                id: 'INDUSTRIAL_NETWORK_DISCOVERY',
                name: 'Industrial Network Discovery',
                type: 'network_discovery',
                pattern: /industrial.*network.*discovery|EtherNet\/IP.*discovery|SCADA.*enumeration/i,
                severity: 'HIGH',
                description: 'Detects industrial network discovery attempts',
                category: 'network_reconnaissance'
            },
            {
                id: 'SCADA_SYSTEM_ENUMERATION',
                name: 'SCADA System Enumeration',
                type: 'system_enumeration',
                pattern: /SCADA.*system.*enumeration|industrial.*system.*scan|PLC.*enumeration/i,
                severity: 'HIGH',
                description: 'Detects systematic SCADA system enumeration',
                category: 'network_reconnaissance'
            }
        ];
        
        // Set total rule count for monitoring
        this.totalRules = this.rules.length;
        this.log('INFO', `Initialized comprehensive IDS rule set with ${this.totalRules} rules`);
    }

    ensureLogDirectory() {
        const logDir = path.dirname(this.logFile);
        if (!fs.existsSync(logDir)) {
            fs.mkdirSync(logDir, { recursive: true });
        }
    }

    startMonitoring() {
        if (this.isRunning) {
            return { success: false, message: 'IDS is already running' };
        }

        this.isRunning = true;
        this.log('INFO', 'IDS Threat Hunter started');
        
        // Start real-time monitoring
        this.monitoringInterval = setInterval(() => {
            this.performThreatHunt();
        }, 5000); // Check every 5 seconds

        // Simulate network monitoring
        this.simulateNetworkMonitoring();
        
        this.emit('monitoring-started');
        return { success: true, message: 'IDS Threat Hunter started successfully' };
    }

    stopMonitoring() {
        if (!this.isRunning) {
            return { success: false, message: 'IDS is not running' };
        }

        this.isRunning = false;
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
            this.monitoringInterval = null;
        }

        this.log('INFO', 'IDS Threat Hunter stopped');
        this.emit('monitoring-stopped');
        return { success: true, message: 'IDS Threat Hunter stopped successfully' };
    }

    performThreatHunt() {
        // Simulate threat hunting activities
        const huntingActivities = [
            this.checkNetworkAnomalities(),
            this.analyzeSystemLogs(),
            this.detectSuspiciousProcesses(),
            this.monitorFileIntegrity(),
            this.analyzeDNSQueries(),
            this.checkUserBehavior()
        ];

        Promise.all(huntingActivities)
            .then(results => {
                const threats = results.filter(result => result && result.threat);
                threats.forEach(threat => this.processThreat(threat));
            })
            .catch(error => {
                this.log('ERROR', `Threat hunting error: ${error.message}`);
            });
    }

    async checkNetworkAnomalities() {
        // Simulate network anomaly detection
        const anomalyChance = Math.random();
        if (anomalyChance < 0.1) { // 10% chance of detecting anomaly
            return {
                threat: true,
                type: 'network',
                severity: 'MEDIUM',
                source: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
                description: 'Unusual network traffic pattern detected',
                timestamp: new Date().toISOString(),
                details: {
                    bytes_transferred: Math.floor(Math.random() * 1000000) + 100000,
                    connection_count: Math.floor(Math.random() * 100) + 50,
                    protocol: Math.random() > 0.5 ? 'TCP' : 'UDP'
                }
            };
        }
        return null;
    }

    async analyzeSystemLogs() {
        // Simulate system log analysis
        const logAnomalyChance = Math.random();
        if (logAnomalyChance < 0.05) { // 5% chance
            return {
                threat: true,
                type: 'system',
                severity: 'HIGH',
                source: 'System Logs',
                description: 'Suspicious system activity detected in logs',
                timestamp: new Date().toISOString(),
                details: {
                    log_source: Math.random() > 0.5 ? 'Windows Event Log' : 'System Journal',
                    event_count: Math.floor(Math.random() * 50) + 10,
                    affected_services: ['Authentication', 'Network', 'File System']
                }
            };
        }
        return null;
    }

    async detectSuspiciousProcesses() {
        // Simulate process monitoring
        const processAnomalyChance = Math.random();
        if (processAnomalyChance < 0.08) { // 8% chance
            const suspiciousProcesses = ['svchost.exe', 'rundll32.exe', 'powershell.exe', 'cmd.exe'];
            return {
                threat: true,
                type: 'process',
                severity: 'HIGH',
                source: 'Process Monitor',
                description: 'Suspicious process behavior detected',
                timestamp: new Date().toISOString(),
                details: {
                    process_name: suspiciousProcesses[Math.floor(Math.random() * suspiciousProcesses.length)],
                    pid: Math.floor(Math.random() * 9999) + 1000,
                    cpu_usage: Math.floor(Math.random() * 100),
                    memory_usage: Math.floor(Math.random() * 1024) + 100
                }
            };
        }
        return null;
    }

    async monitorFileIntegrity() {
        // Simulate file integrity monitoring
        const fileAnomalyChance = Math.random();
        if (fileAnomalyChance < 0.03) { // 3% chance
            const criticalFiles = ['C:\\Windows\\System32\\ntoskrnl.exe', 'C:\\Windows\\System32\\kernel32.dll', '/etc/passwd', '/bin/bash'];
            return {
                threat: true,
                type: 'file',
                severity: 'CRITICAL',
                source: 'File Integrity Monitor',
                description: 'Critical system file modification detected',
                timestamp: new Date().toISOString(),
                details: {
                    file_path: criticalFiles[Math.floor(Math.random() * criticalFiles.length)],
                    modification_type: Math.random() > 0.5 ? 'Modified' : 'Accessed',
                    hash_changed: true,
                    size_change: Math.floor(Math.random() * 1000)
                }
            };
        }
        return null;
    }

    async analyzeDNSQueries() {
        // Simulate DNS analysis
        const dnsAnomalyChance = Math.random();
        if (dnsAnomalyChance < 0.06) { // 6% chance
            const suspiciousDomains = ['malware.com', 'phishing-site.net', 'c2-server.org', 'data-exfil.co'];
            return {
                threat: true,
                type: 'dns',
                severity: 'HIGH',
                source: 'DNS Monitor',
                description: 'Suspicious DNS query detected',
                timestamp: new Date().toISOString(),
                details: {
                    domain: suspiciousDomains[Math.floor(Math.random() * suspiciousDomains.length)],
                    query_type: Math.random() > 0.5 ? 'A' : 'AAAA',
                    source_ip: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
                    response_code: 'NXDOMAIN'
                }
            };
        }
        return null;
    }

    async checkUserBehavior() {
        // Simulate user behavior analysis
        const behaviorAnomalyChance = Math.random();
        if (behaviorAnomalyChance < 0.04) { // 4% chance
            return {
                threat: true,
                type: 'user_behavior',
                severity: 'MEDIUM',
                source: 'User Behavior Analytics',
                description: 'Anomalous user behavior pattern detected',
                timestamp: new Date().toISOString(),
                details: {
                    user_id: `user_${Math.floor(Math.random() * 100)}`,
                    login_time: 'Off-hours',
                    location_anomaly: true,
                    access_pattern: 'Unusual file access pattern',
                    risk_score: Math.floor(Math.random() * 100) + 50
                }
            };
        }
        return null;
    }

    processThreat(threatData) {
        const threat = {
            id: this.generateThreatId(),
            ...threatData,
            status: 'ACTIVE',
            detected_at: new Date().toISOString()
        };

        this.threats.unshift(threat);
        
        // Keep only last 1000 threats
        if (this.threats.length > 1000) {
            this.threats = this.threats.slice(0, 1000);
        }

        this.log('ALERT', `Threat detected: ${threat.description}`, threat);
        this.emit('threat-detected', threat);

        // Check if we need to raise an alert
        this.checkAlertThreshold(threat);
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
                threats: recentThreats.slice(0, 5), // Include first 5 threats
                timestamp: new Date().toISOString(),
                recommended_actions: [
                    'Investigate source systems immediately',
                    'Consider network isolation of affected systems',
                    'Review security logs for additional indicators',
                    'Notify security team and management'
                ]
            };

            this.log('CRITICAL', `Security Alert: ${alert.message}`, alert);
            this.emit('security-alert', alert);
        }
    }

    simulateNetworkMonitoring() {
        // Simulate network events
        const networkEvents = [
            'Connection established from 192.168.1.100 to external server',
            'Unusual bandwidth spike detected on interface eth0',
            'Multiple failed connection attempts from 192.168.1.50',
            'Port scan detected from external IP 203.0.113.42',
            'DNS query to suspicious domain blocked'
        ];

        setInterval(() => {
            if (this.isRunning && Math.random() < 0.3) { // 30% chance every interval
                const event = networkEvents[Math.floor(Math.random() * networkEvents.length)];
                this.analyzeNetworkEvent(event);
            }
        }, 10000); // Every 10 seconds
    }

    analyzeNetworkEvent(eventText) {
        const matchedRules = this.rules.filter(rule => rule.pattern.test(eventText));
        
        matchedRules.forEach(rule => {
            const threat = {
                threat: true,
                type: rule.type,
                severity: rule.severity,
                source: 'Network Monitor',
                description: `${rule.name}: ${eventText}`,
                rule_id: rule.id,
                timestamp: new Date().toISOString(),
                details: {
                    event_text: eventText,
                    rule_triggered: rule.name,
                    confidence: Math.floor(Math.random() * 40) + 60 // 60-100%
                }
            };

            this.processThreat(threat);
        });
    }

    getThreatStatistics() {
        const now = Date.now();
        const last24Hours = this.threats.filter(threat => {
            const threatTime = new Date(threat.detected_at).getTime();
            return (now - threatTime) < 86400000; // 24 hours
        });

        const severityCount = last24Hours.reduce((acc, threat) => {
            acc[threat.severity] = (acc[threat.severity] || 0) + 1;
            return acc;
        }, {});

        const typeCount = last24Hours.reduce((acc, threat) => {
            acc[threat.type] = (acc[threat.type] || 0) + 1;
            return acc;
        }, {});

        return {
            total_threats: this.threats.length,
            threats_24h: last24Hours.length,
            active_threats: this.threats.filter(t => t.status === 'ACTIVE').length,
            severity_distribution: severityCount,
            type_distribution: typeCount,
            monitoring_status: this.isRunning ? 'ACTIVE' : 'STOPPED',
            last_threat: this.threats.length > 0 ? this.threats[0] : null
        };
    }

    getRecentThreats(limit = 50) {
        return this.threats.slice(0, limit);
    }

    getThreatById(threatId) {
        return this.threats.find(threat => threat.id === threatId);
    }

    updateThreatStatus(threatId, status, resolution = null) {
        const threat = this.getThreatById(threatId);
        if (threat) {
            threat.status = status;
            threat.updated_at = new Date().toISOString();
            if (resolution) {
                threat.resolution = resolution;
            }
            
            this.log('INFO', `Threat ${threatId} status updated to ${status}`);
            this.emit('threat-updated', threat);
            return threat;
        }
        return null;
    }

    generateThreatReport() {
        const stats = this.getThreatStatistics();
        const recentThreats = this.getRecentThreats(10);
        
        const report = {
            report_id: this.generateReportId(),
            generated_at: new Date().toISOString(),
            summary: stats,
            recent_threats: recentThreats,
            recommendations: this.generateRecommendations(stats),
            monitoring_config: {
                alert_threshold: this.alertThreshold,
                detection_window: this.detectionWindow,
                active_rules: this.rules.length
            }
        };

        this.log('INFO', `Threat report generated: ${report.report_id}`);
        return report;
    }

    generateRecommendations(stats) {
        const recommendations = [];

        if (stats.threats_24h > 10) {
            recommendations.push({
                priority: 'HIGH',
                action: 'Investigate security posture',
                description: 'High number of threats detected in last 24 hours'
            });
        }

        if (stats.severity_distribution.CRITICAL > 0) {
            recommendations.push({
                priority: 'CRITICAL',
                action: 'Immediate response required',
                description: 'Critical threats require immediate attention'
            });
        }

        if (stats.type_distribution.network > 5) {
            recommendations.push({
                priority: 'MEDIUM',
                action: 'Review network security controls',
                description: 'Multiple network-based threats detected'
            });
        }

        return recommendations;
    }

    log(level, message, data = null) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            level,
            message,
            data: data || {}
        };

        // Write to log file
        const logLine = JSON.stringify(logEntry) + '\n';
        fs.appendFileSync(this.logFile, logLine);

        // Emit log event for real-time display
        this.emit('log-entry', logEntry);
    }

    generateThreatId() {
        return `THR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    generateAlertId() {
        return `ALT-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    generateReportId() {
        return `RPT-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    // Real-time connection management for WebSocket
    addRealtimeConnection(connectionId) {
        this.realtimeConnections.add(connectionId);
    }

    removeRealtimeConnection(connectionId) {
        this.realtimeConnections.delete(connectionId);
    }

    // File System Monitoring Methods
    startFileSystemMonitoring(paths = null) {
        if (this.fileSystemEnabled) {
            return { success: false, message: 'File system monitoring already enabled' };
        }

        try {
            // Default paths to monitor if none provided
            const defaultPaths = [
                os.platform() === 'win32' ? process.env.USERPROFILE : os.homedir(), // User home directory
                os.platform() === 'win32' ? 'C:\\Windows\\System32' : '/etc', // System directory
                process.cwd(), // Current working directory
                path.join(__dirname, '..') // Project directory
            ];

            const pathsToMonitor = paths || defaultPaths;
            this.monitoredPaths = pathsToMonitor;

            pathsToMonitor.forEach(monitorPath => {
                if (fs.existsSync(monitorPath)) {
                    const watcher = chokidar.watch(monitorPath, {
                        ignored: /(^|[\/\\])\../, // ignore dotfiles
                        persistent: true,
                        ignoreInitial: true,
                        depth: 3 // Monitor up to 3 levels deep
                    });

                    // File/directory added
                    watcher.on('add', (filePath) => {
                        this.handleFileSystemEvent('FILE_CREATED', filePath, 'File created');
                    });

                    // File changed
                    watcher.on('change', (filePath) => {
                        this.handleFileSystemEvent('FILE_MODIFIED', filePath, 'File modified');
                    });

                    // File/directory removed
                    watcher.on('unlink', (filePath) => {
                        this.handleFileSystemEvent('FILE_DELETED', filePath, 'File deleted');
                    });

                    // Directory added
                    watcher.on('addDir', (dirPath) => {
                        this.handleFileSystemEvent('DIRECTORY_CREATED', dirPath, 'Directory created');
                    });

                    // Directory removed
                    watcher.on('unlinkDir', (dirPath) => {
                        this.handleFileSystemEvent('DIRECTORY_DELETED', dirPath, 'Directory deleted');
                    });

                    // Error handling
                    watcher.on('error', (error) => {
                        this.log('ERROR', `File system watcher error: ${error.message}`, { path: monitorPath });
                    });

                    this.fileWatchers.push({ watcher, path: monitorPath });
                }
            });

            this.fileSystemEnabled = true;
            this.log('INFO', `File system monitoring started for ${this.monitoredPaths.length} paths`, { paths: this.monitoredPaths });
            
            return { 
                success: true, 
                message: `File system monitoring enabled for ${this.monitoredPaths.length} paths`,
                paths: this.monitoredPaths 
            };
        } catch (error) {
            this.log('ERROR', `Failed to start file system monitoring: ${error.message}`);
            return { success: false, message: error.message };
        }
    }

    stopFileSystemMonitoring() {
        if (!this.fileSystemEnabled) {
            return { success: false, message: 'File system monitoring not enabled' };
        }

        try {
            // Close all watchers
            this.fileWatchers.forEach(({ watcher, path }) => {
                watcher.close();
                this.log('INFO', `Stopped monitoring ${path}`);
            });

            this.fileWatchers = [];
            this.monitoredPaths = [];
            this.fileSystemEnabled = false;
            
            this.log('INFO', 'File system monitoring stopped');
            return { success: true, message: 'File system monitoring stopped' };
        } catch (error) {
            this.log('ERROR', `Failed to stop file system monitoring: ${error.message}`);
            return { success: false, message: error.message };
        }
    }

    handleFileSystemEvent(eventType, filePath, description) {
        try {
            // Get file stats if file still exists
            let fileStats = null;
            let fileSize = 0;
            
            try {
                if (fs.existsSync(filePath)) {
                    fileStats = fs.statSync(filePath);
                    fileSize = fileStats.size;
                }
            } catch (statsError) {
                // File might have been deleted, that's okay
            }

            // Determine severity based on file type and location
            let severity = 'LOW';
            const fileName = path.basename(filePath).toLowerCase();
            const fileDir = path.dirname(filePath).toLowerCase();

            // Critical system files
            if (fileDir.includes('system32') || fileDir.includes('/etc') || fileDir.includes('/bin')) {
                severity = 'CRITICAL';
            }
            // Executable files
            else if (fileName.endsWith('.exe') || fileName.endsWith('.bat') || fileName.endsWith('.cmd') || 
                     fileName.endsWith('.ps1') || fileName.endsWith('.sh') || fileName.endsWith('.dll')) {
                severity = 'HIGH';
            }
            // Configuration and script files
            else if (fileName.endsWith('.config') || fileName.endsWith('.conf') || fileName.endsWith('.ini') || 
                     fileName.endsWith('.json') || fileName.endsWith('.xml') || fileName.endsWith('.js')) {
                severity = 'MEDIUM';
            }

            // Create threat object
            const threat = {
                threat: true,
                type: 'file_system',
                severity: severity,
                source: 'File System Monitor',
                description: `${description}: ${filePath}`,
                timestamp: new Date().toISOString(),
                details: {
                    event_type: eventType,
                    file_path: filePath,
                    file_name: path.basename(filePath),
                    file_directory: path.dirname(filePath),
                    file_extension: path.extname(filePath),
                    file_size: fileSize,
                    user: this.currentUser,
                    platform: os.platform(),
                    hostname: os.hostname(),
                    process_id: process.pid,
                    working_directory: process.cwd()
                }
            };

            // Process the threat through normal threat processing
            this.processThreat(threat);

            // Also emit a specific file system event
            this.emit('file-system-event', {
                type: eventType,
                path: filePath,
                user: this.currentUser,
                timestamp: new Date().toISOString(),
                severity: severity
            });

        } catch (error) {
            this.log('ERROR', `Error handling file system event: ${error.message}`, { 
                eventType, 
                filePath 
            });
        }
    }

    getFileSystemStatus() {
        return {
            enabled: this.fileSystemEnabled,
            monitored_paths: this.monitoredPaths,
            active_watchers: this.fileWatchers.length,
            current_user: this.currentUser,
            platform: os.platform(),
            hostname: os.hostname()
        };
    }

    getSystemHealth() {
        const rulesByCategory = this.getRulesByCategory();
        const rulesBySeverity = this.getRulesBySeverity();
        
        return {
            ids_status: this.isRunning ? 'RUNNING' : 'STOPPED',
            file_monitoring: this.fileSystemEnabled ? 'ENABLED' : 'DISABLED',
            uptime: this.isRunning ? process.uptime() : 0,
            threats_in_memory: this.threats.length,
            active_rules: this.rules.length,
            total_rules: this.totalRules,
            rule_categories: Object.keys(rulesByCategory).length,
            rules_by_category: rulesByCategory,
            rules_by_severity: rulesBySeverity,
            realtime_connections: this.realtimeConnections.size,
            monitored_paths: this.monitoredPaths.length,
            file_watchers: this.fileWatchers.length,
            memory_usage: process.memoryUsage(),
            current_user: this.currentUser,
            hostname: os.hostname(),
            platform: os.platform(),
            last_check: new Date().toISOString()
        };
    }
    
    getRulesByCategory() {
        return this.rules.reduce((categories, rule) => {
            const category = rule.category || 'uncategorized';
            if (!categories[category]) {
                categories[category] = [];
            }
            categories[category].push({
                id: rule.id,
                name: rule.name,
                type: rule.type,
                severity: rule.severity
            });
            return categories;
        }, {});
    }
    
    getRulesBySeverity() {
        return this.rules.reduce((severities, rule) => {
            const severity = rule.severity || 'UNKNOWN';
            severities[severity] = (severities[severity] || 0) + 1;
            return severities;
        }, {});
    }
    
    getAllRules() {
        return this.rules.map(rule => ({
            id: rule.id,
            name: rule.name,
            type: rule.type,
            severity: rule.severity,
            description: rule.description,
            category: rule.category || 'uncategorized',
            pattern: rule.pattern.toString()
        }));
    }
    
    getRuleById(ruleId) {
        return this.rules.find(rule => rule.id === ruleId);
    }
    
    searchRules(query) {
        const searchTerm = query.toLowerCase();
        return this.rules.filter(rule => 
            rule.name.toLowerCase().includes(searchTerm) ||
            rule.description.toLowerCase().includes(searchTerm) ||
            rule.type.toLowerCase().includes(searchTerm) ||
            rule.id.toLowerCase().includes(searchTerm) ||
            (rule.category && rule.category.toLowerCase().includes(searchTerm))
        );
    }
}

module.exports = IDSThreatHunter;
