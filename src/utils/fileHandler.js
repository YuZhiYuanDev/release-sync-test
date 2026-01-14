const core = require('@actions/core');
const fs = require('fs').promises;
const fsExtra = require('fs-extra');
const path = require('path');
const glob = require('glob');

function resolveAssetFiles(assetInput) {
    if (!assetInput) {
        core.warning('Asset input is empty or undefined. No asset files will be processed or resolved.');
        return [];
    }

    core.info(`Starting to resolve asset files from raw input: "${assetInput}"`);

    const assetPatterns = assetInput
        .split(/\s+/)
        .map(item => item.trim())
        .filter(Boolean);

    core.info(`Successfully parsed ${assetPatterns.length} valid asset pattern(s): ${JSON.stringify(assetPatterns)}`);

    return assetPatterns
        .flatMap(pattern => {
            core.info(`Processing asset pattern: "${pattern}" to find matching files`);
            const matchedFiles = glob.sync(pattern, { absolute: true, nodir: true });
            
            if (matchedFiles.length > 0) {
                core.info(`Found ${matchedFiles.length} file(s) matching pattern "${pattern}": ${JSON.stringify(matchedFiles)}`);
            } else {
                core.warning(`No files found matching the asset pattern: "${pattern}"`);
            }
            return matchedFiles;
        })
        .filter((filePath, index, self) => {
            const isUnique = self.indexOf(filePath) === index;
            const fileExists = fsExtra.existsSync(filePath);

            if (!fileExists) {
                core.warning(`[File Validation Failed] Asset file does not exist at the resolved path, skipped. File path: "${filePath}", Is file marked as unique: ${isUnique}`);
                return false;
            }

            if (!isUnique) {
                core.info(`[Duplicate File Detected] Skipping duplicate asset file path: "${filePath}". Only unique files will be processed.`);
                return false;
            }

            core.info(`[File Validation Passed] Asset file is unique and exists, will be retained: "${filePath}"`);
            return true;
        });
}

async function getFileInfo(filePath) {
    core.info(`Starting to retrieve detailed file information for: "${filePath}"`);

    try {
        const fileName = path.basename(filePath);
        const fileStat = await fs.stat(filePath);
        const fileContent = await fs.readFile(filePath);

        core.info(`[File Info Retrieved Successfully] File name: "${fileName}", File path: "${filePath}", File size: ${fileStat.size} bytes, Last modified: ${fileStat.mtime.toISOString()}`);

        return {
            name: fileName,
            size: fileStat.size,
            content: fileContent
        };
    } catch (error) {
        core.warning(`[File Info Retrieval Failed] Skipped processing asset file: "${filePath}". Error type: "${error.name}", Error message: "${error.message}", Stack trace snippet: "${error.stack?.substring(0, 200)}..."`);
        return null;
    }
}

module.exports = {
    resolveAssetFiles,
    getFileInfo
};
