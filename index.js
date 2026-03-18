require('dotenv').config();
console.log('VIRUSTOTAL_API_KEY:', process.env.VIRUSTOTAL_API_KEY); // should print your key
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const socketIo = require('socket.io');
const multer = require('multer');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { exec } = require('child_process');
const NmapRunner = require('./utils/nmapRunner');
const VirusTotalAPI = require('./utils/virustotal');
const ReportGenerator = require('./utils/reportGenerator');
const HistoryManager = require('./utils/historyManager');
const IDSThreatHunter = require('./utils/ids');
const IoTICSIDSEngine = require('./utils/iotIcsIdsEngine');
const CryptoUtils = require('./utils/crypto');
const DateHelper = require('./utils/dateHelper');
const storagePaths = require('./utils/storagePaths');
const endpointProtectorHub = require('./utils/endpointProtectorHub');

// Ensure directories exist as soon as the app boots (important for Render disks)
storagePaths.ensureStorageLayout();

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Health endpoint for Render health checks
app.get('/health', (req, res) => {
  res.status(200).json({ ok: true, ts: new Date().toISOString() });
});
// Doc file address reference
app.get('/docs', (req, res) => {
  res.sendFile(require('path').join(__dirname, 'docs', 'index.html'));
});

// Configure multer for file uploads
const upload = multer({
  dest: storagePaths.getUploadsDir(),
  limits: {
    fileSize: 32 * 1024 * 1024 // 32MB limit
  }
});

// Initialize services
const vtApi = new VirusTotalAPI(process.env.VIRUSTOTAL_API_KEY);
const reportGenerator = new ReportGenerator();
const historyManager = new HistoryManager();
const idsSystem = new IDSThreatHunter();
const iotIcsIdsEngine = new IoTICSIDSEngine();

// Role-based access control middleware
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, 'your_jwt_secret', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// VirusTotal API routes
app.post('/api/virustotal/file', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const result = await vtApi.scanFile(req.file.path);
    
    // Clean up uploaded file
    fs.unlink(req.file.path, (err) => {
      if (err) console.error('Error deleting uploaded file:', err);
    });
    
    res.json(result);
  } catch (error) {
    console.error('VirusTotal file scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/virustotal/url', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    const result = await vtApi.scanUrl(url);
    res.json(result);
  } catch (error) {
    console.error('VirusTotal URL scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/virustotal/hash', async (req, res) => {
  try {
    const { hash } = req.body;
    if (!hash) {
      return res.status(400).json({ error: 'Hash is required' });
    }

    const result = await vtApi.scanHash(hash);
    res.json(result);
  } catch (error) {
    console.error('VirusTotal hash scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Route to generate VirusTotal PDF report
app.post('/api/virustotal/generate-report', async (req, res) => {
  try {
    const vtData = req.body;
    
    if (!vtData || !vtData.data) {
      return res.status(400).json({ error: 'Invalid VirusTotal data provided' });
    }
    
    // Create a mock scan data structure for the report generator
    const scanData = {
      target: vtData.data.id || 'Unknown Target',
      pentester: 'Security Analyst',
        startTime: vtData.scanDate ? DateHelper.toISOString(new Date(vtData.scanDate)) : DateHelper.toISOString(),
      duration: 'N/A',
      scanType: `VirusTotal ${vtData.scanType} Scan`,
      status: 'Completed',
      output: generateVirusTotalOutput(vtData)
    };
    
    const pdfBuffer = await reportGenerator.generatePDFReport(scanData);
    
    res.set({
      'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="virustotal-report-${DateHelper.toFilenameString()}.pdf"`
    });
    
    res.send(Buffer.from(pdfBuffer));
    
  } catch (error) {
    console.error('Error generating VirusTotal PDF:', error);
    res.status(500).json({ error: 'Failed to generate PDF report: ' + error.message });
  }
});

function generateVirusTotalOutput(vtData) {
  let output = `VirusTotal Scan Report\n`;
  output += `========================\n\n`;
  output += `Scan Type: ${vtData.scanType.toUpperCase()}\n`;
    output += `Scan Date: ${vtData.scanDate ? DateHelper.toReportString(new Date(vtData.scanDate)) : DateHelper.toReportString()}\n`;
  output += `Resource ID: ${vtData.data.id}\n\n`;
  
  if (vtData.stats) {
    const total = Object.values(vtData.stats).reduce((a, b) => a + b, 0);
    output += `Detection Statistics:\n`;
    output += `- Clean: ${vtData.stats.harmless}/${total}\n`;
    output += `- Malicious: ${vtData.stats.malicious}/${total}\n`;
    output += `- Suspicious: ${vtData.stats.suspicious}/${total}\n`;
    output += `- Undetected: ${vtData.stats.undetected}/${total}\n\n`;
    
    if (vtData.stats.malicious > 0) {
      output += `⚠️  THREAT DETECTED: ${vtData.stats.malicious} engines detected malicious content\n`;
    } else if (vtData.stats.suspicious > 0) {
      output += `⚠️  SUSPICIOUS: ${vtData.stats.suspicious} engines flagged suspicious content\n`;
    } else {
      output += `✅ CLEAN: No threats detected\n`;
    }
  }
  
  output += `\nRaw VirusTotal Data:\n`;
  output += `=====================\n`;
  output += JSON.stringify(vtData.data, null, 2);
  
  return output;
}

// History and Reports API endpoints
app.get('/api/history', async (req, res) => {
  try {
    const history = await historyManager.getHistory();
    res.json(history);
  } catch (error) {
    console.error('Error fetching history:', error);
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

app.get('/api/history/scans', async (req, res) => {
  try {
    const scans = await historyManager.getRecentScans(20);
    res.json(scans);
  } catch (error) {
    console.error('Error fetching scans:', error);
    res.status(500).json({ error: 'Failed to fetch scans' });
  }
});

app.get('/api/history/reports', async (req, res) => {
  try {
    const reports = await historyManager.getRecentReports(20);
    res.json(reports);
  } catch (error) {
    console.error('Error fetching reports:', error);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

// Endpoint Protector REST endpoints
app.get('/api/endpoint-protector/overview', (req, res) => {
  try {
    res.json(endpointProtectorHub.getOverview());
  } catch (error) {
    console.error('Failed to get endpoint overview:', error);
    res.status(500).json({ error: 'Failed to get endpoint overview' });
  }
});

app.get('/api/endpoint-protector/agents', (req, res) => {
  try {
    res.json(endpointProtectorHub.getAgents());
  } catch (error) {
    console.error('Failed to get agent list:', error);
    res.status(500).json({ error: 'Failed to get agent list' });
  }
});

app.get('/api/endpoint-protector/alerts', (req, res) => {
  try {
    res.json(endpointProtectorHub.getAlerts());
  } catch (error) {
    console.error('Failed to get endpoint alerts:', error);
    res.status(500).json({ error: 'Failed to get endpoint alerts' });
  }
});

// Device control endpoint
app.post('/api/endpoint-protector/agents/:agentId/command', (req, res) => {
  try {
    const { agentId } = req.params;
    const { command, params = {} } = req.body;
    const user = req.headers['x-user'] || req.user?.username || 'anonymous';
    
    if (!agentId || !command) {
      return res.status(400).json({ error: 'Agent ID and command are required' });
    }
    
    // Get the agent metadata (includes socket id)
    const agent = endpointProtectorHub.getAgentMeta(agentId);
    
    if (!agent) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    
    // Emit command to the agent via socket
    let agentSocket = agent.socketId ? io.sockets.sockets.get(agent.socketId) : null;
    if (!agentSocket) {
      agentSocket = findAgentSocket(agentId);
      if (agentSocket) {
        endpointProtectorHub.updateSocketId(agentId, agentSocket.id);
      }
    }
    
    if (agentSocket && agentSocket.connected) {
      const commandPayload = { 
        command, 
        params,
        timestamp: new Date().toISOString() 
      };
      
      // Add error handling for socket emission
      try {
        agentSocket.emit('endpoint-protector:command', commandPayload);
        
        // Log audit event
        if (typeof logAuditEvent === 'function') {
          logAuditEvent(user, `COMMAND_${command.toUpperCase()}`, {
            agentId,
            command,
            params,
            agentHostname: agent.hostname
          });
        }
        
        res.json({ 
          success: true, 
          message: `Command "${command}" sent to agent ${agentId}`,
          agentId,
          command,
          params
        });
      } catch (socketError) {
        console.error('Socket emission error:', socketError);
        // Don't mark agent as offline for socket errors - just report the error
        res.status(503).json({ 
          error: 'Agent connection unstable', 
          showInDashboard: true,
          details: 'Command could not be delivered due to connection issues'
        });
      }
    } else {
      // If socket not found or not connected, but don't mark as offline immediately
      // Agent might be in reconnection process
      res.status(503).json({ 
        error: 'Agent is temporarily unavailable', 
        showInDashboard: true,
        details: 'Agent is offline or reconnecting. Try again in a few moments.'
      });
    }
  } catch (error) {
    console.error('Failed to send command to agent:', error);
    res.status(500).json({ 
      error: 'Failed to send command to agent',
      showInDashboard: true
    });
  }
});

// Audit log storage (in-memory, should be persisted in production)
const auditLogs = [];
const MAX_AUDIT_LOGS = 1000;

function logAuditEvent(user, action, details) {
  const logEntry = {
    id: require('crypto').randomUUID(),
    user: user || 'system',
    action,
    details,
    timestamp: new Date().toISOString(),
    ip: 'N/A' // Could extract from req.ip in production
  };
  auditLogs.unshift(logEntry);
  if (auditLogs.length > MAX_AUDIT_LOGS) {
    auditLogs.pop();
  }
  console.log(`[AUDIT] ${user || 'system'} - ${action}:`, details);
  return logEntry;
}

// Audit logs endpoint
app.get('/api/endpoint-protector/audit-logs', (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const filteredLogs = auditLogs.slice(0, limit);
    res.json({
      success: true,
      total: auditLogs.length,
      logs: filteredLogs
    });
  } catch (error) {
    console.error('Failed to get audit logs:', error);
    res.status(500).json({ error: 'Failed to get audit logs' });
  }
});

app.get('/api/reports', async (req, res) => {
  try {
    const reports = await reportGenerator.getReports();
    res.json(reports);
  } catch (error) {
    console.error('Error fetching reports list:', error);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

app.get('/api/reports/:filename', (req, res) => {
  try {
    const { filename } = req.params;
    const filepath = path.join(storagePaths.getReportsDir(), filename);
    
    // Security check
    if (!filename.match(/^[a-zA-Z0-9_\-\.]+$/)) {
      return res.status(400).json({ error: 'Invalid filename' });
    }
    
    res.sendFile(filepath, (err) => {
      if (err) {
        console.error('Error serving report:', err);
        res.status(404).json({ error: 'Report not found' });
      }
    });
  } catch (error) {
    console.error('Error serving report:', error);
    res.status(500).json({ error: 'Failed to serve report' });
  }
});

app.delete('/api/history/scans/:scanId', async (req, res) => {
  try {
    const { scanId } = req.params;
    const success = await historyManager.deleteScan(scanId);
    if (success) {
      res.json({ success: true });
    } else {
      res.status(404).json({ error: 'Scan not found' });
    }
  } catch (error) {
    console.error('Error deleting scan:', error);
    res.status(500).json({ error: 'Failed to delete scan' });
  }
});

app.post('/api/reports/generate', async (req, res) => {
  try {
    const { scanData, format = 'html' } = req.body;
    
    if (!scanData || !scanData.output) {
      return res.status(400).json({ error: 'Invalid scan data' });
    }
    
    const result = await reportGenerator.saveReport(scanData, format);
    
    if (result.success) {
      // Add to history
      await historyManager.addReport({
        reportId: result.reportId,
        filename: result.filename,
        target: scanData.target,
        format: format.toUpperCase(),
        size: result.size,
        filepath: result.filepath
      });
      
      res.json(result);
    } else {
      res.status(500).json(result);
    }
  } catch (error) {
    console.error('Error generating report:', error);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

// Secure scan endpoint using NmapRunner for consistency
app.post('/scan', authenticateToken, (req, res) => {
  const { target, scanType } = req.body;
  if (!target || !scanType) return res.sendStatus(400);

  // Validate target using the same validation as Socket.IO handler
  if (!NmapRunner.validateTarget(target)) {
    return res.status(400).json({ error: 'Invalid target format' });
  }

  // Process target to extract domain from URL if needed
  const processedTarget = NmapRunner.processTarget(target);
  
  console.log(`REST API Scan: ${processedTarget} with command: ${scanType}`);
  
  // Use NmapRunner for consistent and secure execution
  NmapRunner.executeScan(processedTarget, scanType, '', (error, result) => {
    if (error && !result) {
      return res.status(500).json({ error: error });
    }
    
    if (result && result.type === 'complete') {
      return res.json({ 
        status: 'completed',
        output: result.data,
        target: processedTarget,
        originalTarget: target
      });
    } else if (result && result.type === 'error') {
      return res.status(500).json({ 
        error: result.data,
        exitCode: result.exitCode
      });
    }
  });
});

// IDS/Threat Hunter API endpoints
app.get('/api/ids/status', (req, res) => {
  try {
    const status = idsSystem.getSystemHealth();
    res.json(status);
  } catch (error) {
    console.error('Error getting IDS status:', error);
    res.status(500).json({ error: 'Failed to get IDS status' });
  }
});

app.post('/api/ids/start', (req, res) => {
  try {
    const result = idsSystem.startMonitoring();
    res.json(result);
  } catch (error) {
    console.error('Error starting IDS:', error);
    res.status(500).json({ error: 'Failed to start IDS' });
  }
});

app.post('/api/ids/stop', (req, res) => {
  try {
    const result = idsSystem.stopMonitoring();
    res.json(result);
  } catch (error) {
    console.error('Error stopping IDS:', error);
    res.status(500).json({ error: 'Failed to stop IDS' });
  }
});

app.get('/api/ids/threats', (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const threats = idsSystem.getRecentThreats(limit);
    res.json(threats);
  } catch (error) {
    console.error('Error getting threats:', error);
    res.status(500).json({ error: 'Failed to get threats' });
  }
});

app.get('/api/ids/statistics', (req, res) => {
  try {
    const stats = idsSystem.getThreatStatistics();
    res.json(stats);
  } catch (error) {
    console.error('Error getting IDS statistics:', error);
    res.status(500).json({ error: 'Failed to get IDS statistics' });
  }
});

app.post('/api/ids/threats/:threatId/update', (req, res) => {
  try {
    const { threatId } = req.params;
    const { status, resolution } = req.body;
    
    const updatedThreat = idsSystem.updateThreatStatus(threatId, status, resolution);
    if (updatedThreat) {
      res.json(updatedThreat);
    } else {
      res.status(404).json({ error: 'Threat not found' });
    }
  } catch (error) {
    console.error('Error updating threat:', error);
    res.status(500).json({ error: 'Failed to update threat' });
  }
});

app.get('/api/ids/report', (req, res) => {
  try {
    const report = idsSystem.generateThreatReport();
    res.json(report);
  } catch (error) {
    console.error('Error generating IDS report:', error);
    res.status(500).json({ error: 'Failed to generate IDS report' });
  }
});

// File System Monitoring API endpoints
app.post('/api/ids/start-file-monitoring', (req, res) => {
  try {
    const { paths } = req.body;
    const result = idsSystem.startFileSystemMonitoring(paths);
    res.json(result);
  } catch (error) {
    console.error('Error starting file system monitoring:', error);
    res.status(500).json({ error: 'Failed to start file system monitoring' });
  }
});

app.post('/api/ids/stop-file-monitoring', (req, res) => {
  try {
    const result = idsSystem.stopFileSystemMonitoring();
    res.json(result);
  } catch (error) {
    console.error('Error stopping file system monitoring:', error);
    res.status(500).json({ error: 'Failed to stop file system monitoring' });
  }
});

app.get('/api/ids/file-monitoring-status', (req, res) => {
  try {
    const status = idsSystem.getFileSystemStatus();
    res.json(status);
  } catch (error) {
    console.error('Error getting file system monitoring status:', error);
    res.status(500).json({ error: 'Failed to get file system monitoring status' });
  }
});

// IDS Rules Management API endpoints
app.get('/api/ids/rules', (req, res) => {
  try {
    const rules = idsSystem.getAllRules();
    res.json({
      success: true,
      total_rules: rules.length,
      rules: rules
    });
  } catch (error) {
    console.error('Error getting IDS rules:', error);
    res.status(500).json({ error: 'Failed to get IDS rules' });
  }
});

app.get('/api/ids/rules/categories', (req, res) => {
  try {
    const rulesByCategory = idsSystem.getRulesByCategory();
    res.json({
      success: true,
      categories: Object.keys(rulesByCategory).length,
      rules_by_category: rulesByCategory
    });
  } catch (error) {
    console.error('Error getting IDS rules by category:', error);
    res.status(500).json({ error: 'Failed to get IDS rules by category' });
  }
});

app.get('/api/ids/rules/severity', (req, res) => {
  try {
    const rulesBySeverity = idsSystem.getRulesBySeverity();
    res.json({
      success: true,
      severity_distribution: rulesBySeverity
    });
  } catch (error) {
    console.error('Error getting IDS rules by severity:', error);
    res.status(500).json({ error: 'Failed to get IDS rules by severity' });
  }
});

app.get('/api/ids/rules/:ruleId', (req, res) => {
  try {
    const { ruleId } = req.params;
    const rule = idsSystem.getRuleById(ruleId);
    
    if (rule) {
      res.json({
        success: true,
        rule: {
          id: rule.id,
          name: rule.name,
          type: rule.type,
          severity: rule.severity,
          description: rule.description,
          category: rule.category || 'uncategorized',
          pattern: rule.pattern.toString()
        }
      });
    } else {
      res.status(404).json({ error: 'Rule not found' });
    }
  } catch (error) {
    console.error('Error getting IDS rule:', error);
    res.status(500).json({ error: 'Failed to get IDS rule' });
  }
});

app.get('/api/ids/rules/search/:query', (req, res) => {
  try {
    const { query } = req.params;
    const matchedRules = idsSystem.searchRules(query);
    
    res.json({
      success: true,
      search_query: query,
      matched_rules: matchedRules.length,
      rules: matchedRules.map(rule => ({
        id: rule.id,
        name: rule.name,
        type: rule.type,
        severity: rule.severity,
        description: rule.description,
        category: rule.category || 'uncategorized'
      }))
    });
  } catch (error) {
    console.error('Error searching IDS rules:', error);
    res.status(500).json({ error: 'Failed to search IDS rules' });
  }
});

// IDS Report generation endpoint
app.post('/api/ids/generate-report', async (req, res) => {
  try {
    const reportOptions = req.body;
    
    if (!reportOptions.format) {
      reportOptions.format = 'pdf';
    }
    
    // Generate comprehensive IDS report
    const idsReportData = {
      target: 'Network Infrastructure',
      pentester: reportOptions.auditorName || 'Security Analyst',
        startTime: DateHelper.toISOString(new Date(Date.now() - (24 * 60 * 60 * 1000))), // 24h ago
        endTime: DateHelper.toISOString(),
      duration: reportOptions.timeframe || '24h',
      scanType: 'IDS/Threat Hunter Analysis',
      status: 'Completed',
      output: generateIDSReportContent(reportOptions)
    };
    
    const reportResult = await reportGenerator.saveReport(idsReportData, reportOptions.format);
    
    if (reportResult.success) {
      // Add report to history
      await historyManager.addReport({
        reportId: reportResult.reportId,
        filename: reportResult.filename,
        target: 'IDS/Threat Analysis',
        format: reportOptions.format.toUpperCase(),
        size: reportResult.size,
        filepath: reportResult.filepath,
        pentester: reportOptions.auditorName || 'Security Analyst'
      });
      
      if (reportOptions.format === 'json') {
        res.json({
          success: true,
          filename: reportResult.filename,
          reportId: reportResult.reportId,
          downloadUrl: `/api/reports/${reportResult.filename}`
        });
      } else {
        // Stream the file for direct download
        res.set({
          'Content-Type': getContentType(reportOptions.format),
          'Content-Disposition': `attachment; filename="${reportResult.filename}"`
        });
        
        const filepath = path.join(storagePaths.getReportsDir(), reportResult.filename);
        res.sendFile(filepath, (err) => {
          if (err) {
            console.error('Error sending file:', err);
            res.status(500).json({ error: 'Failed to download report' });
          }
        });
      }
    } else {
      res.status(500).json({ error: reportResult.error || 'Failed to generate report' });
    }
  } catch (error) {
    console.error('Error generating IDS report:', error);
    res.status(500).json({ error: 'Failed to generate IDS report: ' + error.message });
  }
});

function getContentType(format) {
  switch (format.toLowerCase()) {
    case 'pdf': return 'application/pdf';
    case 'html': return 'text/html';
    case 'txt': return 'text/plain';
    case 'json': return 'application/json';
    default: return 'application/octet-stream';
  }
}

function generateIDSReportContent(options) {
  const threats = idsSystem.getRecentThreats(100);
  const statistics = idsSystem.getThreatStatistics();
  const systemHealth = idsSystem.getSystemHealth();
  
  let content = `Intrusion Detection System Security Report\n`;
  content += `=============================================\n\n`;
    content += `Report Generated: ${DateHelper.toReportString()}\n`;
  content += `Analyst: ${options.auditorName || 'Security Analyst'}\n`;
  content += `Organization: ${options.organizationName || 'N/A'}\n`;
  content += `Timeframe: ${options.timeframe || '24h'}\n\n`;
  
  if (options.includeSections?.summary !== false) {
    content += `EXECUTIVE SUMMARY\n`;
    content += `=================\n`;
    content += `Total Threats Detected: ${statistics.total_threats || 0}\n`;
    content += `Threats in Last 24h: ${statistics.threats_24h || 0}\n`;
    content += `System Status: ${systemHealth.ids_status || 'Unknown'}\n`;
    content += `Uptime: ${formatUptime(systemHealth.uptime || 0)}\n\n`;
    
    const severity = statistics.severity_distribution || {};
    content += `Threat Severity Distribution:\n`;
    content += `- Critical: ${severity.CRITICAL || 0}\n`;
    content += `- High: ${severity.HIGH || 0}\n`;
    content += `- Medium: ${severity.MEDIUM || 0}\n`;
    content += `- Low: ${severity.LOW || 0}\n\n`;
  }
  
  if (options.includeSections?.threats !== false) {
    content += `THREAT ANALYSIS\n`;
    content += `===============\n`;
    
    if (threats.length === 0) {
      content += `No threats detected in the specified timeframe.\n\n`;
    } else {
      threats.forEach((threat, index) => {
        content += `${index + 1}. ${threat.severity} - ${threat.type.toUpperCase()}\n`;
        content += `   Description: ${threat.description}\n`;
        content += `   Source: ${threat.source}\n`;
        content += `   Detected: ${DateHelper.toLocaleString(threat.detected_at)}\n`;
        content += `   Status: ${threat.status || 'ACTIVE'}\n`;
        if (threat.details) {
          content += `   Details: ${JSON.stringify(threat.details, null, 2)}\n`;
        }
        content += `\n`;
      });
    }
  }
  
  if (options.includeSections?.statistics !== false) {
    content += `SECURITY STATISTICS\n`;
    content += `==================\n`;
    content += `Active Rules: ${systemHealth.active_rules || 0}\n`;
    content += `Real-time Connections: ${systemHealth.realtime_connections || 0}\n`;
    content += `Threats in Memory: ${systemHealth.threats_in_memory || 0}\n\n`;
  }
  
  if (options.includeSections?.recommendations !== false) {
    content += `RECOMMENDATIONS\n`;
    content += `===============\n`;
    content += `1. Regularly update threat detection rules\n`;
    content += `2. Monitor system performance and adjust thresholds\n`;
    content += `3. Investigate all critical and high-severity threats\n`;
    content += `4. Implement automated response procedures\n`;
    content += `5. Review and tune false positive rates\n`;
    content += `6. Ensure proper logging and retention policies\n`;
    content += `7. Conduct regular security assessments\n\n`;
  }
  
  if (options.includeSections?.logs && options.includeLogs) {
    content += `SYSTEM LOGS\n`;
    content += `===========\n`;
    content += `Recent system logs and events would be included here...\n\n`;
  }
  
  if (options.notes) {
    content += `ADDITIONAL NOTES\n`;
    content += `================\n`;
    content += `${options.notes}\n\n`;
  }
  
  content += `Report generated by Automated Penetration Testing Tool\n`;
    content += `Timestamp: ${options.timestamp || DateHelper.toISOString()}\n`;
  
  return content;
}

// IoT/ICS Enhanced IDS API endpoints
app.get('/api/iot-ics-ids/status', (req, res) => {
  try {
    const status = iotIcsIdsEngine.getSystemHealth();
    res.json(status);
  } catch (error) {
    console.error('Error getting IoT/ICS IDS status:', error);
    res.status(500).json({ error: 'Failed to get IoT/ICS IDS status' });
  }
});

app.post('/api/iot-ics-ids/start', (req, res) => {
  try {
    const result = iotIcsIdsEngine.startMonitoring();
    res.json(result);
  } catch (error) {
    console.error('Error starting IoT/ICS IDS:', error);
    res.status(500).json({ error: 'Failed to start IoT/ICS IDS' });
  }
});

app.post('/api/iot-ics-ids/stop', (req, res) => {
  try {
    const result = iotIcsIdsEngine.stopMonitoring();
    res.json(result);
  } catch (error) {
    console.error('Error stopping IoT/ICS IDS:', error);
    res.status(500).json({ error: 'Failed to stop IoT/ICS IDS' });
  }
});

app.get('/api/iot-ics-ids/threats', (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const threats = iotIcsIdsEngine.getRecentThreats(limit);
    res.json(threats);
  } catch (error) {
    console.error('Error getting IoT/ICS threats:', error);
    res.status(500).json({ error: 'Failed to get IoT/ICS threats' });
  }
});

app.get('/api/iot-ics-ids/statistics', (req, res) => {
  try {
    const stats = iotIcsIdsEngine.getThreatStatistics();
    res.json(stats);
  } catch (error) {
    console.error('Error getting IoT/ICS IDS statistics:', error);
    res.status(500).json({ error: 'Failed to get IoT/ICS IDS statistics' });
  }
});

app.post('/api/iot-ics-ids/threats/:threatId/update', (req, res) => {
  try {
    const { threatId } = req.params;
    const { status, resolution } = req.body;
    
    const updatedThreat = iotIcsIdsEngine.updateThreatStatus(threatId, status, resolution);
    if (updatedThreat) {
      res.json(updatedThreat);
    } else {
      res.status(404).json({ error: 'Threat not found' });
    }
  } catch (error) {
    console.error('Error updating IoT/ICS threat:', error);
    res.status(500).json({ error: 'Failed to update IoT/ICS threat' });
  }
});

app.get('/api/iot-ics-ids/report', (req, res) => {
  try {
    const report = iotIcsIdsEngine.generateThreatReport();
    res.json(report);
  } catch (error) {
    console.error('Error generating IoT/ICS IDS report:', error);
    res.status(500).json({ error: 'Failed to generate IoT/ICS IDS report' });
  }
});

// Export IoT/ICS rules to file
app.post('/api/iot-ics-ids/export-rules', (req, res) => {
  try {
    const { format = 'suricata' } = req.body;
    const result = iotIcsIdsEngine.exportRulesToFile(format);
    
    if (result.success) {
      res.json({
        success: true,
        filename: result.filename,
        rules_count: result.rules_count,
        download_url: `/api/rules/${result.filename}`
      });
    } else {
      res.status(500).json({ error: 'Failed to export rules' });
    }
  } catch (error) {
    console.error('Error exporting IoT/ICS rules:', error);
    res.status(500).json({ error: 'Failed to export rules: ' + error.message });
  }
});

// Serve exported rules files
app.get('/api/rules/:filename', (req, res) => {
  try {
    const { filename } = req.params;
    const filepath = path.join(__dirname, 'rules', filename);
    
    // Security check
    if (!filename.match(/^[a-zA-Z0-9_\-\.]+$/)) {
      return res.status(400).json({ error: 'Invalid filename' });
    }
    
    res.set({
      'Content-Type': 'text/plain',
      'Content-Disposition': `attachment; filename="${filename}"`
    });
    
    res.sendFile(filepath, (err) => {
      if (err) {
        console.error('Error serving rules file:', err);
        res.status(404).json({ error: 'Rules file not found' });
      }
    });
  } catch (error) {
    console.error('Error serving rules file:', error);
    res.status(500).json({ error: 'Failed to serve rules file' });
  }
});

// IoT/ICS IDS Report generation endpoint
app.post('/api/iot-ics-ids/generate-report', async (req, res) => {
  try {
    const reportOptions = req.body;
    
    if (!reportOptions.format) {
      reportOptions.format = 'pdf';
    }
    
    // Generate comprehensive IoT/ICS IDS report
    const idsReportData = {
      target: 'IoT/ICS Infrastructure',
      pentester: reportOptions.auditorName || 'Security Analyst',
        startTime: DateHelper.toISOString(new Date(Date.now() - (24 * 60 * 60 * 1000))), // 24h ago
        endTime: DateHelper.toISOString(),
      duration: reportOptions.timeframe || '24h',
      scanType: 'IoT/ICS IDS Analysis',
      status: 'Completed',
      output: generateIoTICSIDSReportContent(reportOptions)
    };
    
    const reportResult = await reportGenerator.saveReport(idsReportData, reportOptions.format);
    
    if (reportResult.success) {
      // Add report to history
      await historyManager.addReport({
        reportId: reportResult.reportId,
        filename: reportResult.filename,
        target: 'IoT/ICS Infrastructure',
        format: reportOptions.format.toUpperCase(),
        size: reportResult.size,
        filepath: reportResult.filepath,
        pentester: reportOptions.auditorName || 'Security Analyst'
      });
      
      if (reportOptions.format === 'json') {
        res.json({
          success: true,
          filename: reportResult.filename,
          reportId: reportResult.reportId,
          download_url: `/api/reports/${reportResult.filename}`
        });
      } else {
        // Stream the file for direct download
        res.set({
          'Content-Type': getContentType(reportOptions.format),
          'Content-Disposition': `attachment; filename="${reportResult.filename}"`
        });
        
        const filepath = path.join(storagePaths.getReportsDir(), reportResult.filename);
        res.sendFile(filepath, (err) => {
          if (err) {
            console.error('Error sending file:', err);
            res.status(500).json({ error: 'Failed to download report' });
          }
        });
      }
    } else {
      res.status(500).json({ error: reportResult.error || 'Failed to generate report' });
    }
  } catch (error) {
    console.error('Error generating IoT/ICS IDS report:', error);
    res.status(500).json({ error: 'Failed to generate IoT/ICS IDS report: ' + error.message });
  }
});

function generateIoTICSIDSReportContent(options) {
  const threats = iotIcsIdsEngine.getRecentThreats(100);
  const statistics = iotIcsIdsEngine.getThreatStatistics();
  const systemHealth = iotIcsIdsEngine.getSystemHealth();
  
  let content = `IoT/ICS/SCADA Intrusion Detection System Security Report\n`;
  content += `=======================================================\n\n`;
    content += `Report Generated: ${DateHelper.toReportString()}\n`;
  content += `Security Analyst: ${options.auditorName || 'Security Analyst'}\n`;
  content += `Organization: ${options.organizationName || 'N/A'}\n`;
  content += `Assessment Period: ${options.timeframe || '24h'}\n\n`;
  
  if (options.includeSections?.executive_summary !== false) {
    content += `EXECUTIVE SUMMARY\n`;
    content += `=================\n`;
    content += `This report provides a comprehensive analysis of IoT, ICS, and SCADA security threats\n`;
    content += `detected by the advanced Intrusion Detection System over the specified timeframe.\n\n`;
    content += `Key Findings:\n`;
    content += `- Total Threats Detected: ${statistics.total_threats || 0}\n`;
    content += `- Critical/High Severity Threats: ${(statistics.severity_distribution.CRITICAL || 0) + (statistics.severity_distribution.HIGH || 0)}\n`;
    content += `- Industrial Protocol Attacks: ${(statistics.protocol_breakdown.modbus || 0) + (statistics.protocol_breakdown.dnp3 || 0)}\n`;
    content += `- IoT Device Compromises: ${statistics.protocol_breakdown.mqtt || 0}\n`;
    content += `- System Status: ${systemHealth.ids_status || 'Unknown'}\n`;
    content += `- Detection Rate: ${statistics.detection_rate || 'N/A'}\n`;
    content += `- False Positive Rate: ${statistics.false_positive_rate || 'N/A'}\n\n`;
  }
  
  if (options.includeSections?.threat_analysis !== false) {
    content += `DETAILED THREAT ANALYSIS\n`;
    content += `========================\n`;
    
    // Group threats by category
    const threatsByCategory = {};
    threats.forEach(threat => {
      const category = threat.type.toUpperCase();
      if (!threatsByCategory[category]) {
        threatsByCategory[category] = [];
      }
      threatsByCategory[category].push(threat);
    });
    
    Object.keys(threatsByCategory).forEach(category => {
      content += `\n${category} Threats (${threatsByCategory[category].length}):\n`;
      content += `${'='.repeat(category.length + 20)}\n`;
      
      threatsByCategory[category].slice(0, 10).forEach((threat, index) => {
        content += `${index + 1}. [${threat.severity}] ${threat.description}\n`;
        content += `   Source: ${threat.source} → Target: ${threat.target}\n`;
        content += `   Protocol: ${threat.protocol.toUpperCase()} Port: ${threat.port}\n`;
        content += `   Detection Time: ${DateHelper.toLocaleString(threat.detected_at)}\n`;
        content += `   Confidence: ${threat.confidence}% | Status: ${threat.status}\n`;
        if (threat.details) {
          content += `   Context: ${JSON.stringify(threat.details, null, 2).replace(/\n/g, '\n   ')}\n`;
        }
        content += `   Actions Taken: ${threat.actions_taken.join(', ')}\n\n`;
      });
    });
  }
  
  if (options.includeSections?.protocol_analysis !== false) {
    content += `INDUSTRIAL PROTOCOL SECURITY ANALYSIS\n`;
    content += `=====================================\n`;
    const protocols = statistics.protocol_breakdown;
    content += `Modbus Threats: ${protocols.modbus || 0}\n`;
    content += `DNP3 Threats: ${protocols.dnp3 || 0}\n`;
    content += `MQTT/IoT Threats: ${protocols.mqtt || 0}\n`;
    content += `HTTP/Web Interface Threats: ${protocols.http || 0}\n`;
    content += `SSH/Remote Access Threats: ${protocols.ssh || 0}\n`;
    content += `Other Protocol Threats: ${protocols.other || 0}\n\n`;
    
    if (protocols.modbus > 0) {
      content += `MODBUS SECURITY CONCERNS:\n`;
      content += `- Unauthorized write commands detected\n`;
      content += `- Invalid function codes observed\n`;
      content += `- Recommend implementing Modbus security gateways\n\n`;
    }
    
    if (protocols.dnp3 > 0) {
      content += `DNP3 SECURITY CONCERNS:\n`;
      content += `- Unauthorized control operations detected\n`;
      content += `- Recommend enabling DNP3 Secure Authentication\n\n`;
    }
  }
  
  if (options.includeSections?.file_monitoring !== false) {
    content += `FILE SYSTEM MONITORING RESULTS\n`;
    content += `==============================\n`;
    content += `File Monitoring Status: ${systemHealth.file_monitoring || 'DISABLED'}\n`;
    if (systemHealth.file_monitoring === 'ENABLED') {
      content += `- Configuration file changes monitored\n`;
      content += `- Critical system file access logged\n`;
      content += `- User activity tracked for compliance\n`;
    }
    content += `\n`;
  }
  
  if (options.includeSections?.recommendations !== false) {
    content += `SECURITY RECOMMENDATIONS\n`;
    content += `========================\n`;
    
    const recommendations = iotIcsIdsEngine.generateRecommendations(statistics);
    recommendations.forEach((rec, index) => {
      content += `${index + 1}. [${rec.priority}] ${rec.title}\n`;
      content += `   Description: ${rec.description}\n`;
      content += `   Action: ${rec.action}\n\n`;
    });
    
    // Additional IoT/ICS specific recommendations
    content += `IoT/ICS SPECIFIC RECOMMENDATIONS:\n`;
    content += `- Implement network segmentation between IT/OT networks\n`;
    content += `- Deploy industrial firewalls with deep packet inspection\n`;
    content += `- Enable anomaly detection for industrial protocols\n`;
    content += `- Establish baseline behavior for critical control systems\n`;
    content += `- Implement multi-factor authentication for SCADA access\n`;
    content += `- Regular security assessments of industrial networks\n`;
    content += `- Incident response plan specific to industrial systems\n\n`;
  }
  
  if (options.includeSections?.rule_effectiveness !== false) {
    content += `DETECTION RULE EFFECTIVENESS\n`;
    content += `===========================\n`;
    const ruleEffectiveness = iotIcsIdsEngine.calculateRuleEffectiveness();
    
    content += `Top Performing Rules:\n`;
    ruleEffectiveness.slice(0, 10).forEach((rule, index) => {
      content += `${index + 1}. ${rule.description}\n`;
      content += `   Hit Count: ${rule.hit_count}\n`;
      content += `   Effectiveness Score: ${rule.effectiveness_score}/100\n`;
      content += `   Last Triggered: ${rule.last_triggered || 'Never'}\n\n`;
    });
  }
  
  if (options.notes) {
    content += `ADDITIONAL NOTES\n`;
    content += `================\n`;
    content += `${options.notes}\n\n`;
  }
  
  content += `TECHNICAL SPECIFICATIONS\n`;
  content += `=======================\n`;
  content += `Detection Engine: IoT/ICS Enhanced IDS v1.0\n`;
  content += `Active Rules: ${systemHealth.active_rules || 0}\n`;
  content += `System Uptime: ${formatUptime(systemHealth.uptime || 0)}\n`;
  content += `Memory Usage: ${systemHealth.memory_usage || 'N/A'}\n`;
  content += `CPU Usage: ${systemHealth.cpu_usage || 'N/A'}\n\n`;
  
  content += `Report generated by Enhanced Penetration Testing Tool\n`;
  content += `IoT/ICS/SCADA Security Analysis Module\n`;
    content += `Timestamp: ${options.timestamp || DateHelper.toISOString()}\n`;
  
  return content;
}

function formatUptime(seconds) {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  
  if (hours > 0) return `${hours}h ${minutes}m ${secs}s`;
  if (minutes > 0) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

// Enhanced Cryptography API endpoints
app.get('/api/crypto/algorithms', (req, res) => {
  try {
    const algorithms = CryptoUtils.getSupportedAlgorithms();
    res.json(algorithms);
  } catch (error) {
    console.error('Error getting crypto algorithms:', error);
    res.status(500).json({ error: 'Failed to get algorithms' });
  }
});

app.get('/api/crypto/algorithms/:algorithm', (req, res) => {
  try {
    const { algorithm } = req.params;
    const info = CryptoUtils.getAlgorithmInfo(algorithm);
    
    if (info) {
      res.json(info);
    } else {
      res.status(404).json({ error: 'Algorithm not found' });
    }
  } catch (error) {
    console.error('Error getting algorithm info:', error);
    res.status(500).json({ error: 'Failed to get algorithm info' });
  }
});

app.post('/api/crypto/encrypt', (req, res) => {
  try {
    const { algorithm, text, key, options } = req.body;
    
    if (!algorithm || !text || !key) {
      return res.status(400).json({ error: 'Algorithm, text, and key are required' });
    }
    
    const result = CryptoUtils.encrypt(algorithm, text, key, options || {});
    res.json(result);
  } catch (error) {
    console.error('Encryption error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/crypto/decrypt', (req, res) => {
  try {
    const { algorithm, encryptedData, key, options } = req.body;
    
    if (!algorithm || !encryptedData || !key) {
      return res.status(400).json({ error: 'Algorithm, encrypted data, and key are required' });
    }
    
    const result = CryptoUtils.decrypt(algorithm, encryptedData, key, options || {});
    res.json({ decrypted: result });
  } catch (error) {
    console.error('Decryption error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/crypto/hash', (req, res) => {
  try {
    const { text, algorithm = 'sha256' } = req.body;
    
    if (!text) {
      return res.status(400).json({ error: 'Text is required' });
    }
    
    const result = CryptoUtils.hash(text, algorithm);
    res.json({ hash: result, algorithm });
  } catch (error) {
    console.error('Hashing error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/crypto/hmac', (req, res) => {
  try {
    const { text, key, algorithm = 'sha256' } = req.body;
    
    if (!text || !key) {
      return res.status(400).json({ error: 'Text and key are required' });
    }
    
    const result = CryptoUtils.hmac(text, key, algorithm);
    res.json({ hmac: result, algorithm });
  } catch (error) {
    console.error('HMAC error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Encoding/Decoding endpoints
app.post('/api/crypto/encode/:type', (req, res) => {
  try {
    const { type } = req.params;
    const { text } = req.body;
    
    if (!text) {
      return res.status(400).json({ error: 'Text is required' });
    }
    
    let result;
    switch (type.toLowerCase()) {
      case 'base64':
        result = CryptoUtils.base64Encode(text);
        break;
      case 'url':
        result = CryptoUtils.urlEncode(text);
        break;
      case 'hex':
        result = CryptoUtils.hexEncode(text);
        break;
      case 'binary':
        result = CryptoUtils.binaryEncode(text);
        break;
      case 'caesar':
        const shift = parseInt(req.body.shift) || 3;
        result = CryptoUtils.caesarCipher(text, shift);
        break;
      case 'rot13':
        result = CryptoUtils.rot13(text);
        break;
      case 'atbash':
        result = CryptoUtils.atbash(text);
        break;
      default:
        return res.status(400).json({ error: 'Unsupported encoding type' });
    }
    
    res.json({ encoded: result, type });
  } catch (error) {
    console.error('Encoding error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/crypto/decode/:type', (req, res) => {
  try {
    const { type } = req.params;
    const { text } = req.body;
    
    if (!text) {
      return res.status(400).json({ error: 'Text is required' });
    }
    
    let result;
    switch (type.toLowerCase()) {
      case 'base64':
        result = CryptoUtils.base64Decode(text);
        break;
      case 'url':
        result = CryptoUtils.urlDecode(text);
        break;
      case 'hex':
        result = CryptoUtils.hexDecode(text);
        break;
      case 'binary':
        result = CryptoUtils.binaryDecode(text);
        break;
      case 'caesar':
        const shift = parseInt(req.body.shift) || 3;
        result = CryptoUtils.caesarDecipher(text, shift);
        break;
      case 'rot13':
        result = CryptoUtils.rot13(text); // ROT13 is its own inverse
        break;
      case 'atbash':
        result = CryptoUtils.atbash(text); // Atbash is its own inverse
        break;
      default:
        return res.status(400).json({ error: 'Unsupported decoding type' });
    }
    
    res.json({ decoded: result, type });
  } catch (error) {
    console.error('Decoding error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Key generation endpoints
app.post('/api/crypto/generate-key', (req, res) => {
  try {
    const { length = 32 } = req.body;
    const key = CryptoUtils.generateRandomKey(length);
    res.json({ key, length });
  } catch (error) {
    console.error('Key generation error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/crypto/generate-iv', (req, res) => {
  try {
    const { length = 16 } = req.body;
    const iv = CryptoUtils.generateRandomIV(length);
    res.json({ iv, length });
  } catch (error) {
    console.error('IV generation error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/crypto/derive-key', (req, res) => {
  try {
    const { password, salt, iterations = 10000, keyLength = 32, digest = 'sha256' } = req.body;
    
    if (!password || !salt) {
      return res.status(400).json({ error: 'Password and salt are required' });
    }
    
    const derivedKey = CryptoUtils.deriveKey(password, salt, iterations, keyLength, digest);
    res.json({ derivedKey, iterations, keyLength, digest });
  } catch (error) {
    console.error('Key derivation error:', error);
    res.status(500).json({ error: error.message });
  }
});

const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
  console.log('Endpoint Protector control plane ready');
  console.log('IoT/ICS Enhanced IDS Engine ready');
  console.log('Enhanced Cryptography tools ready');
});

// Allow remote agents (Python Socket.IO) to connect cross-origin (Render-hosted service)
let io = socketIo(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

function findAgentSocket(agentId) {
  if (!io || !agentId) return null;
  const direct = io.sockets.sockets.get(agentId);
  if (direct) return direct;
  for (const socket of io.sockets.sockets.values()) {
    if (socket?.data?.agentId === agentId) {
      return socket;
    }
  }
  return null;
}

// Endpoint Protector hub to Socket.IO bridge
endpointProtectorHub.on('agent-registered', (agent) => {
  io.emit('endpoint-protector:agent-registered', agent);
  io.emit('endpoint-protector:agents', endpointProtectorHub.getAgents());
  io.emit('endpoint-protector:overview', endpointProtectorHub.getOverview());
});

endpointProtectorHub.on('telemetry', (payload) => {
  io.emit('endpoint-protector:telemetry', payload);
  io.emit('endpoint-protector:overview', endpointProtectorHub.getOverview());
});

endpointProtectorHub.on('alert', (alert) => {
  io.emit('endpoint-protector:alert', alert);
});

endpointProtectorHub.on('agent-status', (agent) => {
  io.emit('endpoint-protector:agent-status', agent);
  io.emit('endpoint-protector:overview', endpointProtectorHub.getOverview());
});

// IDS real-time event handlers
idsSystem.on('threat-detected', (threat) => {
  io.emit('ids-threat', threat);
});

idsSystem.on('security-alert', (alert) => {
  io.emit('ids-alert', alert);
});

idsSystem.on('log-entry', (logEntry) => {
  io.emit('ids-log', logEntry);
});

// File system event handler
idsSystem.on('file-system-event', (fileEvent) => {
  io.emit('ids-file-system-event', fileEvent);
});

// IoT/ICS IDS real-time event handlers
iotIcsIdsEngine.on('iot-threat-detected', (threat) => {
  io.emit('iot-ics-threat', threat);
});

iotIcsIdsEngine.on('ics-security-alert', (alert) => {
  io.emit('iot-ics-alert', alert);
});

iotIcsIdsEngine.on('protocol-anomaly', (anomaly) => {
  io.emit('iot-ics-anomaly', anomaly);
});

iotIcsIdsEngine.on('device-status-change', (statusChange) => {
  io.emit('iot-ics-device-status', statusChange);
});

iotIcsIdsEngine.on('log-entry', (logEntry) => {
  io.emit('iot-ics-log', logEntry);
});

io.on('connection', (socket) => {
  console.log('New client connected');
  
  // Register client for IDS real-time updates
  const connectionId = socket.id;
  idsSystem.addRealtimeConnection(connectionId);
  
  // Register client for IoT/ICS IDS real-time updates
  iotIcsIdsEngine.addRealtimeConnection(connectionId);

  // Endpoint Protector dashboard requests
  socket.on('endpoint-protector:get-overview', () => {
    const overview = endpointProtectorHub.getOverview();
    socket.emit('endpoint-protector:overview', overview);
    console.log(`[Backend] Sent overview to client: ${overview.total} agents`);
  });

  socket.on('endpoint-protector:get-agents', () => {
    const agents = endpointProtectorHub.getAgents();
    socket.emit('endpoint-protector:agents', agents);
    console.log(`[Backend] Sent ${agents.length} agents to client`);
  });

  socket.on('endpoint-protector:get-alerts', () => {
    const alerts = endpointProtectorHub.getAlerts(100);
    socket.emit('endpoint-protector:alerts', alerts);
    console.log(`[Backend] Sent ${alerts.length} alerts to client`);
  });

  // Endpoint Protector agent channel
  socket.on('endpoint-agent:register', (payload = {}, ack) => {
    try {
      // Validate API key if provided
      const apiKey = payload.apiKey;
      const organizationId = payload.organizationId || 'default-org';
      
      // In production, validate API key against database
      // For now, we'll accept any key or no key (dev mode)
      if (apiKey && apiKey !== 'dev-agent' && apiKey.length < 10) {
        if (typeof ack === 'function') {
          ack({ success: false, error: 'Invalid API key' });
        }
        return;
      }
      
      const agent = endpointProtectorHub.registerAgent({ 
        ...payload, 
        socketId: socket.id,
        organizationId: organizationId
      });
      socket.data = socket.data || {};
      socket.data.role = 'endpoint-agent';
      socket.data.agentId = agent.agentId;
      socket.data.organizationId = organizationId;
      
      // Log audit event
      if (typeof logAuditEvent === 'function') {
        logAuditEvent('system', 'AGENT_REGISTERED', {
          agentId: agent.agentId,
          hostname: agent.hostname,
          organizationId: organizationId,
          platform: agent.platform
        });
      }
      
      // Send acknowledgment (Python socketio client expects ack callback)
      if (typeof ack === 'function') {
        ack({ success: true, agentId: agent.agentId, organizationId: organizationId });
      }
      
      // BROADCAST IMMEDIATELY to all clients
      io.emit('endpoint-protector:agent-registered', agent);
      io.emit('endpoint-protector:agent-status', { agentId: agent.agentId, status: 'ONLINE', agent });
      
      // Also broadcast updated lists to ensure dashboards catch up
      io.emit('endpoint-protector:agents', endpointProtectorHub.getAgents());
      io.emit('endpoint-protector:overview', endpointProtectorHub.getOverview());
      
      console.log(`[Endpoint Protector] Agent registered: ${agent.agentId} (${agent.hostname}) [Org: ${organizationId}]`);
    } catch (error) {
      console.error('Endpoint agent registration failed:', error);
      if (typeof ack === 'function') {
        ack({ success: false, error: error.message });
      }
    }
  });

  socket.on('endpoint-agent:telemetry', (payload = {}) => {
    const agentId = payload.agentId || socket.data?.agentId;
    if (!agentId) {
      console.warn('[Backend] Telemetry received without agentId:', payload);
      return;
    }
    endpointProtectorHub.updateSocketId(agentId, socket.id);
    // Ensure the agent is registered even if we missed the initial registration event
    if (!endpointProtectorHub.hasAgent(agentId)) {
      const telemetry = payload.telemetry || {};
      const fallbackHostname = telemetry?.network?.hostname
        || telemetry?.system?.hostname
        || payload.hostname
        || agentId;
      const fallbackPlatform = telemetry?.os
        ? `${telemetry.os.name || ''} ${telemetry.os.version || ''}`.trim()
        : payload.platform;
      endpointProtectorHub.ensureAgent(agentId, {
        hostname: fallbackHostname,
        platform: fallbackPlatform || `${os.platform()} ${os.release()}`,
        ipAddress: telemetry?.network?.external_ip
          || telemetry?.network?.interfaces?.[0]?.addresses?.[0]
          || payload.ipAddress,
        tags: telemetry?.system?.roles || payload.tags,
        owner: payload.owner,
        socketId: socket.id,
        telemetry
      });
    }
    const telemetry = payload.telemetry || payload;
    if (payload.ipAddress) {
      telemetry.ipAddress = payload.ipAddress;
    } else if (telemetry?.network?.primaryIp) {
      telemetry.ipAddress = telemetry.network.primaryIp;
    }
    const updated = endpointProtectorHub.updateTelemetry(agentId, telemetry);
    if (updated) {
      // Broadcast to all clients
      io.emit('endpoint-protector:telemetry', updated);
      // Also update agent status
      io.emit('endpoint-protector:agent-status', updated);
      io.emit('endpoint-protector:overview', endpointProtectorHub.getOverview());
      io.emit('endpoint-protector:agents', endpointProtectorHub.getAgents());
      console.log(`[Backend] Telemetry update from agent ${agentId}`);
    }
    // Handle events/alerts in payload
    if (Array.isArray(payload.events) && payload.events.length > 0) {
      payload.events.forEach(event => {
        const alert = endpointProtectorHub.recordAlert(agentId, event);
        io.emit('endpoint-protector:alert', alert);
      });
    }
  });

  socket.on('endpoint-agent:alert', ({ agentId, events = [] } = {}) => {
    const resolvedAgentId = agentId || socket.data?.agentId;
    events.forEach(event => {
      const alert = endpointProtectorHub.recordAlert(resolvedAgentId, event);
      io.emit('endpoint-protector:alert', alert);
    });
  });

  socket.on('endpoint-agent:heartbeat', () => {
    const agentId = socket.data?.agentId;
    if (!agentId) return;
    
    // update socket id to ensure connectivity
    endpointProtectorHub.updateSocketId(agentId, socket.id);
    
    const status = endpointProtectorHub.touchAgent(agentId);
    if (status) {
      io.emit('endpoint-protector:agent-status', status);
    }
  });

  // Handle device control commands from dashboard (via socket)
  socket.on('endpoint-protector:command', ({ agentId, command, params = {} }) => {
    const user = socket.data?.user || 'anonymous';
    const agents = endpointProtectorHub.getAgents();
    const agent = agents.find(a => a.agentId === agentId);
    if (agent && agent.socketId) {
      let agentSocket = io.sockets.sockets.get(agent.socketId);
      if (!agentSocket) {
        agentSocket = findAgentSocket(agentId);
        if (agentSocket) {
          endpointProtectorHub.updateSocketId(agentId, agentSocket.id);
        }
      }
      if (agentSocket) {
        const commandPayload = { 
          command, 
          params,
          timestamp: new Date().toISOString() 
        };
        agentSocket.emit('endpoint-protector:command', commandPayload);
        
        // Log audit event
        logAuditEvent(user, `COMMAND_${command.toUpperCase()}`, {
          agentId,
          command,
          params,
          agentHostname: agent.hostname
        });
        
        console.log(`[Endpoint Protector] Command "${command}" sent to agent ${agentId} by ${user}`);
      } else {
        console.warn(`[Endpoint Protector] Agent ${agentId} socket not found`);
      }
    } else {
      console.warn(`[Endpoint Protector] Agent ${agentId} not found`);
    }
  });

  socket.on('disconnect', () => {
    endpointProtectorHub.markSocketDisconnected(socket.id);
  });

  socket.on('start-scan', async (data) => {
    console.log('Scan started:', data);
    const { target, command, pentester = 'Security Analyst' } = data;
    const startTime = new Date();
    let scanEntry = null;

    // Validate target
    if (!NmapRunner.validateTarget(target)) {
      return socket.emit('scan-progress', {
        status: 'Failed',
        message: { text: 'Invalid target format', type: 'error' }
      });
    }

    // Process target to extract domain from URL if needed
    const processedTarget = NmapRunner.processTarget(target);
    
    // Add scan to history
    try {
      scanEntry = await historyManager.addScan({
        target: processedTarget,
        scanType: command,
        status: 'In Progress',
        startTime: DateHelper.toISOString(startTime),
        pentester
      });
    } catch (error) {
      console.error('Error adding scan to history:', error);
    }
    
    socket.emit('scan-progress', {
      status: 'Starting scan...',
      progress: 0,
      message: { text: `Starting scan of ${processedTarget} (from ${target})...`, type: 'info' },
      scanId: scanEntry?.id
    });

    let fullOutput = '';

    NmapRunner.executeScan(processedTarget, command, '', async (error, result) => {
      if (error && !result) {
        // Update history with failure
        if (scanEntry) {
          await historyManager.updateScanStatus(scanEntry.id, 'Failed', DateHelper.toISOString());
        }
        
        return socket.emit('scan-progress', {
          status: 'Failed',
          message: { text: error, type: 'error' },
          scanId: scanEntry?.id
        });
      }

      if (result) {
        if (result.type === 'stdout' || result.type === 'stderr') {
          fullOutput += result.data;
        }
        
        if (result.type === 'stdout') {
          socket.emit('scan-progress', {
            status: 'Scanning...',
            message: { text: result.data, type: 'info' },
            scanId: scanEntry?.id
          });
        } else if (result.type === 'stderr') {
          socket.emit('scan-progress', {
            status: 'Scanning...',
            message: { text: result.data, type: 'warning' },
            scanId: scanEntry?.id
          });
        } else if (result.type === 'complete') {
          const endTime = new Date();
          const duration = Math.round((endTime - startTime) / 1000);
          
          // Update history with completion
          if (scanEntry) {
            await historyManager.updateScanStatus(
              scanEntry.id, 
              'Completed', 
              DateHelper.toISOString(endTime),
              fullOutput
            );
          }
          
            // Auto-generate professional PDF report
            try {
                const scanData = {
                    target: processedTarget,
                    scanType: command,
                    status: 'Completed',
                    startTime: startTime,
                    endTime: endTime,
                    duration: `${duration}s`,
                    pentester: pentester,
                    output: fullOutput
                };
                
                // Generate PDF report by default
                const reportResult = await reportGenerator.saveReport(scanData, 'pdf');
                
                if (reportResult.success) {
                    // Add report to history
                    await historyManager.addReport({
                        reportId: reportResult.reportId,
                        scanId: scanEntry?.id,
                        filename: reportResult.filename,
                        target: processedTarget,
                        format: 'PDF',
                        size: reportResult.size,
                        filepath: reportResult.filepath,
                        pentester
                    });
                    
                    socket.emit('scan-progress', {
                        status: 'Completed',
                        progress: 100,
                        message: { text: `Scan completed! Professional PDF report generated: ${reportResult.filename}`, type: 'success' },
                        scanId: scanEntry?.id,
                        reportGenerated: true,
                        reportFilename: reportResult.filename,
                        reportId: reportResult.reportId
                    });
                } else {
                    socket.emit('scan-progress', {
                        status: 'Completed',
                        progress: 100,
                        message: { text: 'Scan completed successfully! (PDF report generation failed)', type: 'success' },
                        scanId: scanEntry?.id,
                        reportGenerated: false
                    });
                }
            } catch (reportError) {
                console.error('Error generating report:', reportError);
                socket.emit('scan-progress', {
                    status: 'Completed',
                    progress: 100,
                    message: { text: 'Scan completed successfully! (Report generation failed)', type: 'success' },
                    scanId: scanEntry?.id,
                    reportGenerated: false
                });
            }
          
        } else if (result.type === 'error') {
          // Update history with error
          if (scanEntry) {
            await historyManager.updateScanStatus(
              scanEntry.id, 
              'Failed', 
              DateHelper.toISOString(),
              fullOutput
            );
          }
          
          socket.emit('scan-progress', {
            status: 'Failed',
            message: { text: result.data, type: 'error' },
            scanId: scanEntry?.id
          });
        }
      }
    });
  });

  // IDS-specific WebSocket events
  socket.on('ids-start-monitoring', () => {
    const result = idsSystem.startMonitoring();
    socket.emit('ids-monitoring-response', result);
  });

  socket.on('ids-stop-monitoring', () => {
    const result = idsSystem.stopMonitoring();
    socket.emit('ids-monitoring-response', result);
  });

  socket.on('ids-get-status', () => {
    const status = idsSystem.getSystemHealth();
    socket.emit('ids-status-update', status);
  });

  socket.on('ids-get-threats', (data) => {
    const limit = data?.limit || 50;
    const threats = idsSystem.getRecentThreats(limit);
    socket.emit('ids-threats-update', threats);
  });

  socket.on('ids-get-statistics', () => {
    const stats = idsSystem.getThreatStatistics();
    socket.emit('ids-statistics-update', stats);
  });

  socket.on('ids-update-threat', (data) => {
    const { threatId, status, resolution } = data;
    const updatedThreat = idsSystem.updateThreatStatus(threatId, status, resolution);
    if (updatedThreat) {
      socket.emit('ids-threat-updated', updatedThreat);
    } else {
      socket.emit('ids-error', { message: 'Threat not found' });
    }
  });

  // IoT/ICS IDS-specific WebSocket events
  socket.on('iot-ics-ids-start-monitoring', () => {
    const result = iotIcsIdsEngine.startMonitoring();
    socket.emit('iot-ics-ids-monitoring-response', result);
  });

  socket.on('iot-ics-ids-stop-monitoring', () => {
    const result = iotIcsIdsEngine.stopMonitoring();
    socket.emit('iot-ics-ids-monitoring-response', result);
  });

  socket.on('iot-ics-ids-get-status', () => {
    const status = iotIcsIdsEngine.getSystemHealth();
    socket.emit('iot-ics-ids-status-update', status);
  });

  socket.on('iot-ics-ids-get-threats', (data) => {
    const limit = data?.limit || 50;
    const threats = iotIcsIdsEngine.getRecentThreats(limit);
    socket.emit('iot-ics-ids-threats-update', threats);
  });

  socket.on('iot-ics-ids-get-statistics', () => {
    const stats = iotIcsIdsEngine.getThreatStatistics();
    socket.emit('iot-ics-ids-statistics-update', stats);
  });

  socket.on('iot-ics-ids-update-threat', (data) => {
    const { threatId, status, resolution } = data;
    const updatedThreat = iotIcsIdsEngine.updateThreatStatus(threatId, status, resolution);
    if (updatedThreat) {
      socket.emit('iot-ics-ids-threat-updated', updatedThreat);
    } else {
      socket.emit('iot-ics-ids-error', { message: 'Threat not found' });
    }
  });

  socket.on('iot-ics-ids-export-rules', (data) => {
    const { format = 'suricata' } = data;
    try {
      const result = iotIcsIdsEngine.exportRulesToFile(format);
      socket.emit('iot-ics-ids-rules-exported', result);
    } catch (error) {
      socket.emit('iot-ics-ids-error', { message: 'Failed to export rules: ' + error.message });
    }
  });

  socket.on('iot-ics-ids-get-device-status', () => {
    try {
      const deviceStatus = iotIcsIdsEngine.getDeviceStatus();
      socket.emit('iot-ics-ids-device-status-update', deviceStatus);
    } catch (error) {
      socket.emit('iot-ics-ids-error', { message: 'Failed to get device status: ' + error.message });
    }
  });

  socket.on('iot-ics-ids-get-protocol-stats', () => {
    try {
      const protocolStats = iotIcsIdsEngine.getProtocolStatistics();
      socket.emit('iot-ics-ids-protocol-stats-update', protocolStats);
    } catch (error) {
      socket.emit('iot-ics-ids-error', { message: 'Failed to get protocol statistics: ' + error.message });
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected');
    // Remove from IDS real-time connections
    idsSystem.removeRealtimeConnection(connectionId);
    // Remove from IoT/ICS IDS real-time connections
    iotIcsIdsEngine.removeRealtimeConnection(connectionId);
    const offlineAgent = endpointProtectorHub.markSocketDisconnected(socket.id);
    if (offlineAgent) {
      io.emit('endpoint-protector:agent-status', offlineAgent);
    }
  });
});
