const { EventEmitter } = require('events');
const os = require('os');
const crypto = require('crypto');

class EndpointProtectorHub extends EventEmitter {
    constructor() {
        super();
        this.endpoints = new Map();
        this.alerts = [];
    }

    generateAgentId(hostname = 'endpoint') {
        const suffix = crypto.randomBytes(4).toString('hex');
        return `${hostname.replace(/[^a-zA-Z0-9]/g, '').toLowerCase() || 'endpoint'}-${suffix}`;
    }

    normalizeTags(tags) {
        if (!tags) return [];
        if (Array.isArray(tags)) return tags.map(tag => String(tag).trim()).filter(Boolean);
        return String(tags)
            .split(',')
            .map(tag => tag.trim())
            .filter(Boolean);
    }

    registerAgent(payload = {}) {
        const agentId = payload.agentId || this.generateAgentId(payload.hostname || payload.deviceName);
        const now = new Date().toISOString();
        const agentRecord = {
            agentId,
            hostname: payload.hostname || payload.deviceName || os.hostname(),
            platform: payload.platform || `${os.platform()} ${os.release()}`,
            ipAddress: payload.ipAddress || payload.ip || 'N/A',
            version: payload.version || '1.0.0',
            status: 'ONLINE',
            tags: this.normalizeTags(payload.tags),
            owner: payload.owner || 'Security Team',
            registeredAt: now,
            lastSeen: now,
            socketId: payload.socketId,
            telemetry: payload.telemetry || {},
            riskScore: 0
        };

        this.endpoints.set(agentRecord.agentId, agentRecord);
        const serialized = this.serialize(agentRecord);
        this.emit('agent-registered', serialized);
        return serialized;
    }

    hasAgent(agentId) {
        return Boolean(agentId) && this.endpoints.has(agentId);
    }

    getAgent(agentId) {
        if (!this.hasAgent(agentId)) {
            return null;
        }
        return this.serialize(this.endpoints.get(agentId));
    }

    getAgentMeta(agentId) {
        if (!this.hasAgent(agentId)) {
            return null;
        }
        const agent = this.endpoints.get(agentId);
        return {
            ...this.serialize(agent),
            socketId: agent.socketId
        };
    }

    ensureAgent(agentId, payload = {}) {
        if (this.hasAgent(agentId)) {
            return this.getAgent(agentId);
        }
        return this.registerAgent({ agentId, ...payload });
    }

    updateTelemetry(agentId, telemetry = {}) {
        if (!agentId || !this.endpoints.has(agentId)) {
            return null;
        }

        const agent = this.endpoints.get(agentId);
        agent.telemetry = {
            cpu: telemetry.cpu || agent.telemetry.cpu || {},
            memory: telemetry.memory || agent.telemetry.memory || {},
            network: telemetry.network || agent.telemetry.network || {},
            disk: telemetry.disk || agent.telemetry.disk || {},
            processes: telemetry.processes || agent.telemetry.processes || [],
            integrity: telemetry.integrity || agent.telemetry.integrity || {},
            // Keep user context for reporting (needed for Windows Event Log PDF metadata)
            users: telemetry.users || agent.telemetry.users || {},
            status: telemetry.status || agent.telemetry.status || 'STABLE',
            timestamp: new Date().toISOString()
        };
        agent.status = telemetry.status || 'ONLINE';
        agent.lastSeen = new Date().toISOString();
        agent.riskScore = this.calculateRiskScore(agent.telemetry);

        const reportedIp = telemetry.ipAddress
            || telemetry.network?.primaryIp
            || telemetry.network?.external_ip;
        if (reportedIp) {
            agent.ipAddress = reportedIp;
        }

        const serialized = this.serialize(agent);
        this.emit('telemetry', serialized);
        return serialized;
    }

    updateSocketId(agentId, socketId) {
        if (!agentId || !socketId || !this.endpoints.has(agentId)) {
            return null;
        }
        const agent = this.endpoints.get(agentId);
        if (agent.socketId !== socketId) {
            agent.socketId = socketId;
        }
        return this.serialize(agent);
    }

    recordAlert(agentId, alertPayload = {}) {
        const agent = this.endpoints.get(agentId);
        // For new file & USB types, allow alertType and details passthrough
        const alertType = alertPayload.alertType || alertPayload.type || 'telemetry';
        let message = alertPayload.message || alertPayload.description || 'Security event detected';
        // Professional-friendly fallback message for specific alert types
        if (!alertPayload.message && alertType) {
            const details = alertPayload.details || {};
            switch (alertType.toUpperCase()) {
                case 'FILE_MODIFIED':
                    message = `File modified: ${(alertPayload.file || details.file || 'Unknown')}`; break;
                case 'FILE_DELETED':
                    message = `File deleted: ${(alertPayload.file || details.file || 'Unknown')}`; break;
                case 'USB_CONNECTED':
                    message = `USB device connected${details.vendor ? `: ${details.vendor} ${details.product || ''}` : ''}`; break;
                case 'USB_DISCONNECTED':
                    message = `USB device disconnected${details.vendor ? `: ${details.vendor} ${details.product || ''}` : ''}`; break;
            }
        }
        const alert = {
            id: crypto.randomUUID(),
            agentId,
            hostname: agent?.hostname || 'Unknown Endpoint',
            severity: alertPayload.severity || alertPayload.level || 'INFO',
            type: alertType,
            alertType,
            message,
            timestamp: new Date().toISOString(),
            details: alertPayload.details || {},
            context: alertPayload.context || {},
            signal: alertPayload.signal || null
        };

        this.alerts.unshift(alert);
        if (this.alerts.length > 200) {
            this.alerts = this.alerts.slice(0, 200);
        }

        this.emit('alert', alert);
        return alert;
    }

    calculateRiskScore(telemetry = {}) {
        const cpuScore = telemetry.cpu?.usage || telemetry.cpu?.load || 0;
        const memScore = telemetry.memory?.utilization || telemetry.memory?.usedPercent || 0;
        const integrityFindings = telemetry.integrity?.alerts || 0;
        const processFindings = telemetry.processes?.filter(proc => proc.suspicious).length || 0;

        const score = Math.min(
            100,
            Math.round(cpuScore * 0.3 + memScore * 0.3 + (integrityFindings + processFindings) * 10)
        );
        return score;
    }

    getOverview() {
        const agents = Array.from(this.endpoints.values());
        const total = agents.length;
        const online = agents.filter(agent => agent.status !== 'OFFLINE').length;
        const critical = agents.filter(agent => agent.riskScore >= 70).length;
        const avgRisk = total > 0 ? Math.round(agents.reduce((sum, agent) => sum + (agent.riskScore || 0), 0) / total) : 0;

        return {
            total,
            online,
            offline: total - online,
            critical,
            avgRisk,
            lastUpdated: new Date().toISOString()
        };
    }

    getAgents() {
        return Array.from(this.endpoints.values())
            .map(agent => this.serialize(agent))
            .sort((a, b) => b.riskScore - a.riskScore);
    }

    getAlerts(limit = 50) {
        return this.alerts.slice(0, limit);
    }

    markAgentOffline(agentId) {
        if (!agentId || !this.endpoints.has(agentId)) {
            return null;
        }
        const agent = this.endpoints.get(agentId);
        agent.status = 'OFFLINE';
        agent.lastSeen = new Date().toISOString();
        const serialized = this.serialize(agent);
        this.emit('agent-status', serialized);
        return serialized;
    }

    markSocketDisconnected(socketId) {
        if (!socketId) return null;
        const [agentId] = Array.from(this.endpoints.entries())
            .find(([, agent]) => agent.socketId === socketId) || [];
        if (!agentId) return null;
        return this.markAgentOffline(agentId);
    }

    touchAgent(agentId) {
        if (!agentId || !this.endpoints.has(agentId)) {
            return null;
        }
        const agent = this.endpoints.get(agentId);
        agent.lastSeen = new Date().toISOString();
        agent.status = agent.status === 'OFFLINE' ? 'ONLINE' : agent.status;
        const serialized = this.serialize(agent);
        this.emit('agent-status', serialized);
        return serialized;
    }

    serialize(agent) {
        return {
            agentId: agent.agentId,
            hostname: agent.hostname,
            platform: agent.platform,
            ipAddress: agent.ipAddress,
            version: agent.version,
            status: agent.status,
            tags: agent.tags,
            owner: agent.owner,
            registeredAt: agent.registeredAt,
            lastSeen: agent.lastSeen,
            telemetry: agent.telemetry,
            riskScore: agent.riskScore
        };
    }
}

module.exports = new EndpointProtectorHub();
