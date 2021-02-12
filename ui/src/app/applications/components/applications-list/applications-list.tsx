import {Autocomplete, ErrorNotification, MockupList, NotificationType, SlidingPanel} from 'argo-ui';
import * as classNames from 'classnames';
import * as minimatch from 'minimatch';
import * as React from 'react';
import {RouteComponentProps} from 'react-router';
import {Observable} from 'rxjs';

import {ClusterCtx, DataLoader, EmptyState, ObservableQuery, Page, Paginate, Query, Spinner} from '../../../shared/components';
import {Consumer, ContextApis} from '../../../shared/context';
import * as models from '../../../shared/models';
import {AppsListPreferences, AppsListViewType, services, ViewPreferences} from '../../../shared/services';
import {ApplicationCreatePanel} from '../application-create-panel/application-create-panel';
import {ApplicationSyncPanel} from '../application-sync-panel/application-sync-panel';
import {ApplicationsSyncPanel} from '../applications-sync-panel/applications-sync-panel';
import * as LabelSelector from '../label-selector';
import * as AppUtils from '../utils';
import {ApplicationsFilter} from './applications-filter';
import {ApplicationsSummary} from './applications-summary';
import {ApplicationsTable} from './applications-table';
import {ApplicationTiles} from './applications-tiles';

require('./applications-list.scss');

const EVENTS_BUFFER_TIMEOUT = 500;
const WATCH_RETRY_TIMEOUT = 500;
const APP_FIELDS = [
    'metadata.name',
    'metadata.annotations',
    'metadata.labels',
    'metadata.creationTimestamp',
    'metadata.deletionTimestamp',
    'spec',
    'operation.sync',
    'status.sync.status',
    'status.health',
    'status.operationState.phase',
    'status.operationState.operation.sync',
    'status.summary'
];
const APP_LIST_FIELDS = ['metadata.resourceVersion', 'metadata.remainingItemCount', ...APP_FIELDS.map(field => `items.${field}`)];
const APP_WATCH_FIELDS = ['result.type', ...APP_FIELDS.map(field => `result.application.${field}`)];

function loadApplications(from: number, count: number): Observable<models.ApplicationList> {
    return Observable.fromPromise(services.applications.list([], {fields: APP_LIST_FIELDS}, from, count)).flatMap(applicationsList => {
        const applications = applicationsList.items;
        const hiddenDataLength = applicationsList.metadata.remainingItemCount;
        return Observable.merge(
            Observable.of({items: applications, metadata: {remainingItemCount: hiddenDataLength}} as models.ApplicationList),
            services.applications
                .watch({resourceVersion: applicationsList.metadata.resourceVersion}, {fields: APP_WATCH_FIELDS})
                .repeat()
                .retryWhen(errors => errors.delay(WATCH_RETRY_TIMEOUT))
                // batch events to avoid constant re-rendering and improve UI performance
                .bufferTime(EVENTS_BUFFER_TIMEOUT)
                .map(appChanges => {
                    appChanges.forEach(appChange => {
                        const index = applications.findIndex(item => item.metadata.name === appChange.application.metadata.name);
                        switch (appChange.type) {
                            case 'DELETED':
                                if (index > -1) {
                                    applications.splice(index, 1);
                                }
                                break;
                            default:
                                if (index > -1) {
                                    applications[index] = appChange.application;
                                } else {
                                    applications.unshift(appChange.application);
                                }
                                break;
                        }
                    });
                    return {applications, updated: appChanges.length > 0};
                })
                .filter(item => item.updated)
                .map(item => {
                    return {items: item.applications, metadata: {remainingItemCount: hiddenDataLength}} as models.ApplicationList;
                })
        );
    });
}

const streamApplications = (): Observable<models.Application[]> => {
    return services.applications
        .watch()
        .map(e => e.application)
        .scan((apps, app) => {
            apps.push(app);
            return apps;
        }, new Array<models.Application>())
        .bufferTime(EVENTS_BUFFER_TIMEOUT)
        .filter(batch => batch.length > 0)
        .map(batch => batch[batch.length - 1]);
};

const ViewPref = ({initPref, children}: {initPref: ViewPreferences; children: (pref: AppsListPreferences & {page: number; search: string}) => React.ReactNode}) => (
    <ObservableQuery>
        {q => (
            <DataLoader
                load={() =>
                    q.map(params => {
                        const viewPref = initPref.appList;
                        if (params.get('proj') != null) {
                            viewPref.projectsFilter = params
                                .get('proj')
                                .split(',')
                                .filter(item => !!item);
                        }
                        if (params.get('sync') != null) {
                            viewPref.syncFilter = params
                                .get('sync')
                                .split(',')
                                .filter(item => !!item);
                        }
                        if (params.get('health') != null) {
                            viewPref.healthFilter = params
                                .get('health')
                                .split(',')
                                .filter(item => !!item);
                        }
                        if (params.get('namespace') != null) {
                            viewPref.namespacesFilter = params
                                .get('namespace')
                                .split(',')
                                .filter(item => !!item);
                        }
                        if (params.get('cluster') != null) {
                            viewPref.clustersFilter = params
                                .get('cluster')
                                .split(',')
                                .filter(item => !!item);
                        }
                        if (params.get('view') != null) {
                            viewPref.view = params.get('view') as AppsListViewType;
                        }
                        if (params.get('labels') != null) {
                            viewPref.labelsFilter = params
                                .get('labels')
                                .split(',')
                                .map(decodeURIComponent)
                                .filter(item => !!item);
                        }
                        return {...viewPref, page: parseInt(params.get('page') || '0', 10), search: params.get('search') || ''};
                    })
                }>
                {pref => children(pref)}
            </DataLoader>
        )}
    </ObservableQuery>
);

function filterApps(applications: models.Application[], pref: AppsListPreferences, search: string) {
    return applications.filter(
        app =>
            (search === '' || app.metadata.name.includes(search)) &&
            (pref.projectsFilter.length === 0 || pref.projectsFilter.includes(app.spec.project)) &&
            (pref.reposFilter.length === 0 || pref.reposFilter.includes(app.spec.source.repoURL)) &&
            (pref.syncFilter.length === 0 || pref.syncFilter.includes(app.status.sync.status)) &&
            (pref.healthFilter.length === 0 || pref.healthFilter.includes(app.status.health.status)) &&
            (pref.namespacesFilter.length === 0 || pref.namespacesFilter.some(ns => app.spec.destination.namespace && minimatch(app.spec.destination.namespace, ns))) &&
            (pref.clustersFilter.length === 0 || pref.clustersFilter.some(server => server.includes(app.spec.destination.server || app.spec.destination.name))) &&
            (pref.labelsFilter.length === 0 || pref.labelsFilter.every(selector => LabelSelector.match(selector, app.metadata.labels)))
    );
}

function tryJsonParse(input: string) {
    try {
        return (input && JSON.parse(input)) || null;
    } catch {
        return null;
    }
}

export const ApplicationsList = (props: RouteComponentProps<{}>) => {
    const query = new URLSearchParams(props.location.search);
    const appInput = tryJsonParse(query.get('new'));
    const syncAppsInput = tryJsonParse(query.get('syncApps'));
    const [createApi, setCreateApi] = React.useState(null);
    const clusters = React.useMemo(() => services.clusters.list(), []);
    const [isAppCreatePending, setAppCreatePending] = React.useState(false);
    const searchBar = React.useRef<HTMLDivElement>(null);

    React.useEffect(() => {
        const handleKeyPress = (e: KeyboardEvent) => {
            if (e.keyCode === 47 && searchBar.current && !appInput) {
                searchBar.current.querySelector('input').focus();
                e.preventDefault();
            }
        };
        document.addEventListener('keypress', handleKeyPress);
        return () => {
            document.removeEventListener('keypress', handleKeyPress);
        };
    });

    const loaderRef = React.useRef<DataLoader>();
    function refreshApp(appName: string) {
        // app refreshing might be done too quickly so that UI might miss it due to event batching
        // add refreshing annotation in the UI to improve user experience
        if (loaderRef.current) {
            const applications = loaderRef.current.getData() as models.Application[];
            const app = applications.find(item => item.metadata.name === appName);
            if (app) {
                AppUtils.setAppRefreshing(app);
                loaderRef.current.setData(applications);
            }
        }
        services.applications.get(appName, 'normal');
    }

    function onFilterPrefChanged(ctx: ContextApis, newPref: AppsListPreferences) {
        services.viewPreferences.updatePreferences({appList: newPref});
        ctx.navigation.goto('.', {
            proj: newPref.projectsFilter.join(','),
            sync: newPref.syncFilter.join(','),
            health: newPref.healthFilter.join(','),
            namespace: newPref.namespacesFilter.join(','),
            cluster: newPref.clustersFilter.join(','),
            labels: newPref.labelsFilter.map(encodeURIComponent).join(',')
        });
    }

    return (
        <ClusterCtx.Provider value={clusters}>
            <Consumer>
                {ctx => (
                    <DataLoader load={() => services.viewPreferences.getPreferences()}>
                        {viewPrefs => (
                            <Page
                                title='Applications'
                                toolbar={{
                                    breadcrumbs: [{title: 'Applications', path: '/applications'}],
                                    tools: (
                                        <React.Fragment key='app-list-tools'>
                                            <span className='applications-list__view-type'>
                                                <i
                                                    className={classNames('fa fa-th', {selected: viewPrefs.appList.view === 'tiles'})}
                                                    title='Tiles'
                                                    onClick={() => {
                                                        ctx.navigation.goto('.', {view: 'tiles'});
                                                        services.viewPreferences.updatePreferences({appList: {...viewPrefs.appList, view: 'tiles'}});
                                                    }}
                                                />
                                                <i
                                                    className={classNames('fa fa-th-list', {selected: viewPrefs.appList.view === 'list'})}
                                                    title='List'
                                                    onClick={() => {
                                                        ctx.navigation.goto('.', {view: 'list'});
                                                        services.viewPreferences.updatePreferences({appList: {...viewPrefs.appList, view: 'list'}});
                                                    }}
                                                />
                                                <i
                                                    className={classNames('fa fa-chart-pie', {selected: viewPrefs.appList.view === 'summary'})}
                                                    title='Summary'
                                                    onClick={() => {
                                                        ctx.navigation.goto('.', {view: 'summary'});
                                                        services.viewPreferences.updatePreferences({appList: {...viewPrefs.appList, view: 'summary'}});
                                                    }}
                                                />
                                            </span>
                                        </React.Fragment>
                                    ),
                                    actionMenu: {
                                        items: [
                                            {
                                                title: 'New App',
                                                iconClassName: 'fa fa-plus',
                                                qeId: 'applications-list-button-new-app',
                                                action: () => ctx.navigation.goto('.', {new: '{}'})
                                            },
                                            {
                                                title: 'Sync Apps',
                                                iconClassName: 'fa fa-sync',
                                                action: () => ctx.navigation.goto('.', {syncApps: true})
                                            }
                                        ]
                                    }
                                }}>
                                <DataLoader load={() => streamApplications()}>{apps => apps.map(a => a.metadata.name)}</DataLoader>
                                <div className='applications-list'>
                                    <ViewPref initPref={viewPrefs}>
                                        {pref => {
                                            const count = viewPrefs.pageSizes['applications-list'] as number;
                                            const from = count * pref.page || 0;
                                            return (
                                                <DataLoader
                                                    ref={loaderRef}
                                                    load={() => AppUtils.handlePageVisibility(() => loadApplications(from, count))}
                                                    loadingRenderer={() => (
                                                        <div className='argo-container'>
                                                            <MockupList height={100} marginTop={30} />
                                                        </div>
                                                    )}>
                                                    {(appList: models.ApplicationList) => {
                                                        const applications = appList.items;
                                                        const filteredApps = filterApps(applications, pref, pref.search);
                                                        const remaining = parseInt(appList.metadata.remainingItemCount, 10);
                                                        const padding = remaining > 0 ? new Array(remaining) : new Array();
                                                        const paddedApplications = new Array(from).concat(filteredApps.concat(padding));
                                                        return applications.length === 0 && (pref.labelsFilter || []).length === 0 ? (
                                                            <EmptyState icon='argo-icon-application'>
                                                                <h4>No applications yet</h4>
                                                                <h5>Create new application to start managing resources in your cluster</h5>
                                                                <button
                                                                    qe-id='applications-list-button-create-application'
                                                                    className='argo-button argo-button--base'
                                                                    onClick={() => ctx.navigation.goto('.', {new: JSON.stringify({})})}>
                                                                    Create application
                                                                </button>
                                                            </EmptyState>
                                                        ) : (
                                                            <div className='row'>
                                                                <div className='columns small-12 xxlarge-2'>
                                                                    <Query>
                                                                        {q => (
                                                                            <div className='applications-list__search' ref={searchBar}>
                                                                                <i
                                                                                    className='fa fa-search'
                                                                                    onClick={() => {
                                                                                        if (searchBar.current) {
                                                                                            searchBar.current.querySelector('input').focus();
                                                                                        }
                                                                                    }}
                                                                                />
                                                                                {q.get('search') && (
                                                                                    <i
                                                                                        className='fa fa-times'
                                                                                        onClick={() => ctx.navigation.goto('.', {search: null}, {replace: true})}
                                                                                    />
                                                                                )}
                                                                                <Autocomplete
                                                                                    filterSuggestions={true}
                                                                                    renderInput={inputProps => (
                                                                                        <input
                                                                                            {...inputProps}
                                                                                            onFocus={e => {
                                                                                                e.target.select();
                                                                                                if (inputProps.onFocus) {
                                                                                                    inputProps.onFocus(e);
                                                                                                }
                                                                                            }}
                                                                                            className='argo-field'
                                                                                            placeholder='Search applications...'
                                                                                        />
                                                                                    )}
                                                                                    renderItem={item => (
                                                                                        <React.Fragment>
                                                                                            <i className='icon argo-icon-application' /> {item.label}
                                                                                        </React.Fragment>
                                                                                    )}
                                                                                    onSelect={val => {
                                                                                        ctx.navigation.goto(`./${val}`);
                                                                                    }}
                                                                                    onChange={e => ctx.navigation.goto('.', {search: e.target.value}, {replace: true})}
                                                                                    value={q.get('search') || ''}
                                                                                    items={applications.map(app => app.metadata.name)}
                                                                                />
                                                                            </div>
                                                                        )}
                                                                    </Query>
                                                                    <DataLoader load={() => services.clusters.list()}>
                                                                        {clusterList => {
                                                                            return (
                                                                                <ApplicationsFilter
                                                                                    clusters={clusterList}
                                                                                    applications={filteredApps}
                                                                                    pref={pref}
                                                                                    onChange={newPref => onFilterPrefChanged(ctx, newPref)}
                                                                                />
                                                                            );
                                                                        }}
                                                                    </DataLoader>

                                                                    {syncAppsInput && (
                                                                        <ApplicationsSyncPanel
                                                                            key='syncsPanel'
                                                                            show={syncAppsInput}
                                                                            hide={() => ctx.navigation.goto('.', {syncApps: null})}
                                                                            apps={filteredApps}
                                                                        />
                                                                    )}
                                                                </div>
                                                                <div className='columns small-12 xxlarge-10'>
                                                                    {(pref.view === 'summary' && <ApplicationsSummary applications={filteredApps} />) || (
                                                                        <Paginate
                                                                            preferencesKey='applications-list'
                                                                            page={pref.page}
                                                                            emptyState={() => (
                                                                                <EmptyState icon='fa fa-search'>
                                                                                    <h4>No matching applications found</h4>
                                                                                    <h5>
                                                                                        Change filter criteria or&nbsp;
                                                                                        <a
                                                                                            onClick={() => {
                                                                                                AppsListPreferences.clearFilters(pref);
                                                                                                onFilterPrefChanged(ctx, pref);
                                                                                            }}>
                                                                                            clear filters
                                                                                        </a>
                                                                                    </h5>
                                                                                </EmptyState>
                                                                            )}
                                                                            data={paddedApplications}
                                                                            onPageChange={page => {
                                                                                loaderRef.current.reload();
                                                                                ctx.navigation.goto('.', {page});
                                                                            }}
                                                                            onPageSizeChange={size => {
                                                                                loaderRef.current.reload();
                                                                            }}>
                                                                            {data =>
                                                                                (pref.view === 'tiles' && (
                                                                                    <ApplicationTiles
                                                                                        applications={data}
                                                                                        syncApplication={appName => ctx.navigation.goto('.', {syncApp: appName})}
                                                                                        refreshApplication={refreshApp}
                                                                                        deleteApplication={appName => AppUtils.deleteApplication(appName, ctx)}
                                                                                    />
                                                                                )) || (
                                                                                    <ApplicationsTable
                                                                                        applications={data}
                                                                                        syncApplication={appName => ctx.navigation.goto('.', {syncApp: appName})}
                                                                                        refreshApplication={refreshApp}
                                                                                        deleteApplication={appName => AppUtils.deleteApplication(appName, ctx)}
                                                                                    />
                                                                                )
                                                                            }
                                                                        </Paginate>
                                                                    )}
                                                                </div>
                                                            </div>
                                                        );
                                                    }}
                                                </DataLoader>
                                            );
                                        }}
                                    </ViewPref>
                                </div>
                                <ObservableQuery>
                                    {q => (
                                        <DataLoader
                                            load={() =>
                                                q.flatMap(params => {
                                                    const syncApp = params.get('syncApp');
                                                    return (syncApp && Observable.fromPromise(services.applications.get(syncApp))) || Observable.from([null]);
                                                })
                                            }>
                                            {app => (
                                                <ApplicationSyncPanel
                                                    key='syncPanel'
                                                    application={app}
                                                    selectedResource={'all'}
                                                    hide={() => ctx.navigation.goto('.', {syncApp: null})}
                                                />
                                            )}
                                        </DataLoader>
                                    )}
                                </ObservableQuery>
                                <SlidingPanel
                                    isShown={!!appInput}
                                    onClose={() => ctx.navigation.goto('.', {new: null})}
                                    header={
                                        <div>
                                            <button
                                                qe-id='applications-list-button-create'
                                                className='argo-button argo-button--base'
                                                disabled={isAppCreatePending}
                                                onClick={() => createApi && createApi.submitForm(null)}>
                                                <Spinner show={isAppCreatePending} style={{marginRight: '5px'}} />
                                                Create
                                            </button>{' '}
                                            <button
                                                qe-id='applications-list-button-cancel'
                                                onClick={() => ctx.navigation.goto('.', {new: null})}
                                                className='argo-button argo-button--base-o'>
                                                Cancel
                                            </button>
                                        </div>
                                    }>
                                    {appInput && (
                                        <ApplicationCreatePanel
                                            getFormApi={api => {
                                                setCreateApi(api);
                                            }}
                                            createApp={async app => {
                                                setAppCreatePending(true);
                                                try {
                                                    await services.applications.create(app);
                                                    ctx.navigation.goto('.', {new: null});
                                                } catch (e) {
                                                    ctx.notifications.show({
                                                        content: <ErrorNotification title='Unable to create application' e={e} />,
                                                        type: NotificationType.Error
                                                    });
                                                } finally {
                                                    setAppCreatePending(false);
                                                }
                                            }}
                                            app={appInput}
                                            onAppChanged={app => ctx.navigation.goto('.', {new: JSON.stringify(app)}, {replace: true})}
                                        />
                                    )}
                                </SlidingPanel>
                            </Page>
                        )}
                    </DataLoader>
                )}
            </Consumer>
        </ClusterCtx.Provider>
    );
};
