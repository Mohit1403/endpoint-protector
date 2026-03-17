// Date Helper for Timezone Management
// Uses Asia/Kolkata timezone for all date operations

class DateHelper {
    constructor() {
        this.timezone = 'Asia/Kolkata';
        this.locale = 'en-IN';
    }

    // Get current date/time in Indian timezone
    now() {
        return new Date();
    }

    // Format date for display in Indian timezone
    toLocaleString(date = new Date()) {
        if (typeof date === 'string' || typeof date === 'number') {
            date = new Date(date);
        }
        
        return date.toLocaleString(this.locale, {
            timeZone: this.timezone,
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
    }

    // Format date for ISO string in Indian timezone
    toISOString(date = new Date()) {
        if (typeof date === 'string' || typeof date === 'number') {
            date = new Date(date);
        }
        return date.toISOString();
    }

    // Format date for reports (detailed format)
    toReportString(date = new Date()) {
        if (typeof date === 'string' || typeof date === 'number') {
            date = new Date(date);
        }
        
        return date.toLocaleString(this.locale, {
            timeZone: this.timezone,
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            timeZoneName: 'short',
            hour12: false
        });
    }

    // Format date for filenames (safe characters)
    toFilenameString(date = new Date()) {
        if (typeof date === 'string' || typeof date === 'number') {
            date = new Date(date);
        }
        
        const formatted = date.toLocaleString(this.locale, {
            timeZone: this.timezone,
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
        
        // Replace unsafe characters for filename
        return formatted.replace(/[\/\\:*?"<>|]/g, '-').replace(/,/g, '').replace(/\s+/g, '-');
    }

    // Get timestamp for database storage
    getTimestamp(date = new Date()) {
        return date.getTime();
    }

    // Parse timestamp from database
    fromTimestamp(timestamp) {
        return new Date(timestamp);
    }

    // Format time ago (relative time)
    getTimeAgo(date) {
        if (typeof date === 'string' || typeof date === 'number') {
            date = new Date(date);
        }
        
        const now = this.now();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);
        
        if (diffMins < 1) return 'just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        if (diffDays < 7) return `${diffDays}d ago`;
        
        return this.toLocaleString(date);
    }

    // Get Indian timezone offset
    getTimezoneOffset() {
        const date = new Date();
        const utc = date.getTime() + (date.getTimezoneOffset() * 60000);
        const istOffset = 5.5; // IST is UTC+5:30
        return new Date(utc + (istOffset * 3600000));
    }

    // Format duration in human readable format
    formatDuration(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = Math.floor(seconds % 60);
        
        if (hours > 0) return `${hours}h ${minutes}m ${secs}s`;
        if (minutes > 0) return `${minutes}m ${secs}s`;
        return `${secs}s`;
    }
}

module.exports = new DateHelper();