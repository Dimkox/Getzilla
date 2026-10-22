/**
 * Node template. Engineering evidence, not legal advice.
 * Returned provenance is unsigned metadata, not embedded marking.
 * Configure trusted c2patool signing separately. Use caller-approved public labels only.
 * This template uses syntax shared by TypeScript and modern JavaScript.
 */
import {spawnSync} from 'node:child_process';
import {copyFileSync, lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {extname, join} from 'node:path';

export const AI_DISCLOSURE = 'You are interacting with an AI system.';
export const IPTC_GENERATED = 'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia';

export function markGeneratedContent(content, {generator, model, media_type, path = null}) {
    const result = {
        content,
        provenance: {digitalSourceType: IPTC_GENERATED, generator, model,
                     created: new Date().toISOString(), media_type},
        c2pa: null,
        c2pa_error: null,
    };
    if (path === null) {
        result.c2pa_error = 'no media path supplied';
        return result;
    }
    let directory;
    try {
        directory = mkdtempSync(join(tmpdir(), 'ai-provenance-'));
        const staged = join(directory, 'input' + extname(path));
        const output = join(directory, 'marked' + extname(path));
        const manifest = join(directory, 'manifest.json');
        copyFileSync(path, staged);
        writeFileSync(manifest, JSON.stringify({claim_generator: generator, assertions: [
            {label: 'c2pa.actions', data: {actions: [
                {action: 'c2pa.created', digitalSourceType: IPTC_GENERATED}]}}]}), 'utf8');
        const completed = spawnSync('c2patool', [staged, '--manifest', manifest, '-o', output],
                                    {timeout: 30000, killSignal: 'SIGKILL', stdio: 'ignore', shell: false});
        if (completed.error) {
            result.c2pa_error = completed.error.code === 'ENOENT' ? 'c2patool not found'
                : completed.error.code === 'ETIMEDOUT' ? 'c2patool timeout' : 'c2patool failed';
        } else if (completed.status !== 0) {
            result.c2pa_error = 'c2patool failed';
        } else if (!lstatSync(output).isFile() || lstatSync(output).isSymbolicLink()) {
            result.c2pa_error = 'c2patool produced no regular output';
        } else {
            result.c2pa = readFileSync(output);
        }
    } catch {
        result.c2pa_error = 'c2patool could not mark the media';
    } finally {
        if (directory) rmSync(directory, {recursive: true, force: true});
    }
    return result;
}

export function labelPublishedContent(text, {label = 'Generated with AI'} = {}) {
    const prefix = label + '\n';
    return text.startsWith(prefix) ? text : prefix + text;
}
