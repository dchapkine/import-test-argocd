import * as React from 'react';
import {revisionUrl} from './urls';

export const Revision = ({repoUrl, revision, path, title, children}: {repoUrl: string; revision: string; path?: string; title?: string; children?: React.ReactNode}) => {
    if (title == 'PATH' && path) {
        // This source literally has no path, so we won't show one.
        return <span></span>
    }
    revision = revision || '';
    const hasPath = path && path !== '.';
    let url = revisionUrl(repoUrl, revision, hasPath);
    if (hasPath) {
        url += '/' + path;
    }
    const content = children || (isSHA(revision) ? revision.substr(0, 7) : revision);
    return url !== null ? (
        <a href={url} target='_blank' rel='noopener noreferrer'>
            {content}
        </a>
    ) : (
        <span>{content}</span>
    );
};

export const isSHA = (revision: string) => {
    // https://stackoverflow.com/questions/468370/a-regex-to-match-a-sha1
    return revision.match(/^[a-f0-9]{5,40}$/) !== null;
};
