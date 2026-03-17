const fs = require('fs');
const path = require('path');

const projectRoot = path.join(__dirname, '..');
const baseStoragePath = process.env.PERSISTENT_STORAGE_PATH
    ? path.resolve(process.env.PERSISTENT_STORAGE_PATH)
    : projectRoot;

const storageMap = {
    dataDir: path.resolve(process.env.DATA_DIR || path.join(baseStoragePath, 'data')),
    reportsDir: path.resolve(process.env.REPORTS_DIR || path.join(baseStoragePath, 'reports')),
    uploadsDir: path.resolve(process.env.UPLOADS_DIR || path.join(baseStoragePath, 'uploads')),
    logsDir: path.resolve(process.env.LOGS_DIR || path.join(baseStoragePath, 'logs'))
};

function ensureDirectory(targetPath) {
    try {
        fs.mkdirSync(targetPath, { recursive: true });
    } catch (error) {
        if (error.code !== 'EEXIST') {
            throw error;
        }
    }
}

function ensureStorageLayout() {
    Object.values(storageMap).forEach(ensureDirectory);
}

module.exports = {
    baseStoragePath,
    ensureDirectory,
    ensureStorageLayout,
    getDataDir: () => storageMap.dataDir,
    getReportsDir: () => storageMap.reportsDir,
    getUploadsDir: () => storageMap.uploadsDir,
    getLogsDir: () => storageMap.logsDir
};





