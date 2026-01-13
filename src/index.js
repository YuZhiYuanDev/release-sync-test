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
