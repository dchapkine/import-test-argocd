import * as React from 'react';
import {ICON_CLASS_BY_KIND} from './utils';

// https://github.com/kubernetes/community/tree/master/icons
// https://docs.google.com/presentation/d/15h_MHjR2fzXIiGZniUdHok_FP07u1L8MAX5cN1r0j4U/edit
const imgNameByKind = new Map<string, string>([
    ['ClusterRole', 'c-role'],
    ['ConfigMap', 'cm'],
    ['ClusterRoleBinding', 'crb'],
    ['CustomResourceDefinition', 'crd'],
    ['CronJob', 'cronjob'],
    ['Deployment', 'deploy'],
    ['DaemonSet', 'ds'],
    ['Endpoint', 'ep'],
    ['Endpoints', 'ep'],
    ['Group', 'group'],
    ['HorizontalPodAutoscaler', 'hpa'],
    ['Ingress', 'ing'],
    ['Job', 'job'],
    ['LimitRange', 'limits'],
    ['NetworkPolicy', 'netpol'],
    ['Namespace', 'ns'],
    ['Pod', 'pod'],
    ['PodSecurityPolicy', 'psp'],
    ['PersistentVolume', 'pv'],
    ['PersistentVolumeClaim', 'pvc'],
    ['Quote', 'quota'],
    ['RoleBinding', 'rb'],
    ['Role', 'role'],
    ['ReplicaSet', 'rs'],
    ['ServiceAccount', 'sa'],
    ['StorageClass', 'sc'],
    ['Secret', 'secret'],
    ['StatefulSet', 'sts'],
    ['Service', 'svc'],
    ['User', 'user'],
    ['Volume', 'vol'],
]);

export const ResourceIcon = ({kind}: { kind: string }) => {
    const img = imgNameByKind.get(kind);
    if (img !== undefined) {
        return (
            <img src={'assets/images/resources/' + img + '.svg'} alt={kind} style={{padding: '2px', width: '40px', height: '32px'}}/>
        );
    }
    const className = ICON_CLASS_BY_KIND[kind.toLocaleLowerCase()];
    if (className !== undefined) {
        return <i title={kind} className={`icon ${className}`}/>;
    }
    return <i title={kind} className='icon fa fa-cogs'/>;
};
