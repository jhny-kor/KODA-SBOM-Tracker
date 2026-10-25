"""Retired connector removal preserves native SBOM and project evidence."""
from sqlalchemy import inspect, select, text
from test_ssvc import setup
from koda_tracker.config import Settings
from koda_tracker.db import remove_retired_connector_schema
from koda_tracker.models import Job, JobState, Role, RolePolicy, SbomRun, Service


def test_upgrade_drops_only_connector_storage_preserves_sbom_and_native_jobs(setup):
    db, client, run, revision = setup
    expected_findings = revision.findings.copy()
    db.add_all([RolePolicy(role=Role.ADMIN, permissions=['runs.view','catalog.manage','ssvc.manage','dtrack.settings','dtrack.retry','migrations.manage']), Job(id='native',kind='analyze',run_id=run.id,state=JobState.QUEUED), Job(id='retired',kind='sync_dependency_track',run_id=run.id,state=JobState.QUEUED)])
    db.commit()
    bind = db.get_bind()
    with bind.begin() as connection:
        for table in ('legacy_migrations','legacy_object_maps','project_sync_sources','project_sync_events'):
            connection.execute(text(f'CREATE TABLE {table} (id TEXT PRIMARY KEY, secret TEXT)'))
            connection.execute(text(f"INSERT INTO {table} VALUES ('old', 'retired credential')"))
        connection.execute(text('ALTER TABLE services ADD COLUMN dtrack_collection_uuid TEXT'))
        for column in ('dtrack_state','dtrack_project_uuid','dtrack_token','dtrack_error','dtrack_metrics','dtrack_policies'):
            connection.execute(text(f'ALTER TABLE sbom_runs ADD COLUMN {column} TEXT NOT NULL DEFAULT \'old\''))
    remove_retired_connector_schema(bind)
    remove_retired_connector_schema(bind)
    db.expire_all()
    assert db.get(SbomRun,run.id).sha256 == 'a'*64
    assert db.get(Service,'s').name == 'SSVC'
    assert revision.findings == expected_findings
    assert db.get(Job,'native').kind == 'analyze' and db.get(Job,'retired') is None
    assert db.get(RolePolicy,Role.ADMIN).permissions == ['runs.view','catalog.manage','ssvc.manage']
    schema = inspect(bind)
    assert not any(column['name'].startswith('dtrack_') for column in schema.get_columns('sbom_runs'))
    assert not {'legacy_migrations','legacy_object_maps','project_sync_sources','project_sync_events'}.intersection(schema.get_table_names())


def test_retired_routes_models_configuration_and_permissions_are_absent():
    from koda_tracker.main import app
    from koda_tracker.security import PERMISSION_CATALOG
    paths = {route.path for route in app.routes if hasattr(route,'path')}
    assert not any('dependency-track' in path or 'legacy-migrations' in path or 'project-sync' in path for path in paths)
    assert not any(name.startswith('dependency_track_') for name in Settings.model_fields)
    assert not any(name.startswith('dtrack_') for name in SbomRun.__mapper__.attrs.keys())
    assert not {'dtrack.settings','dtrack.retry','migrations.manage'}.intersection(PERMISSION_CATALOG)
