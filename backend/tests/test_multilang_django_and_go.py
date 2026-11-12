"""End-to-end 3-tier tests for Python/Django + Vue SFC and Go/sqlc/chi + SvelteKit stacks."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.adapters.autodetect import detect_repository_stack
from app.models import TargetProject
from app.services.scanner_service import run_target_scan


def test_django_orm_drf_and_vue_sfc_lineage_and_line_accurate_findings(
    db_session: Session, tmp_path: Path
) -> None:
    """Verify Django models/migrations + urls/views/services + Vue 3 .vue SFC E2E scan."""
    repo = tmp_path / "django_vue_repo"
    (repo / "backend" / "billing" / "migrations").mkdir(parents=True)
    (repo / "frontend" / "src" / "pages").mkdir(parents=True)

    (repo / "backend" / "manage.py").write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    (repo / "frontend" / "package.json").write_text(
        '{"dependencies": {"vue": "3.5.0"}}',
        encoding="utf-8",
    )
    (repo / "backend" / "billing" / "models.py").write_text(
        """
from django.db import models

class LedgerEntry(models.Model):
    amount = models.IntegerField()

    class Meta:
        db_table = "ledger_entries"
""",
        encoding="utf-8",
    )
    (repo / "backend" / "billing" / "migrations" / "0001_initial.py").write_text(
        """
from django.db import migrations

class Migration(migrations.Migration):
    operations = [
        migrations.CreateModel(
            name="LedgerEntry",
            fields=[],
            options={"db_table": "ledger_entries"},
        ),
    ]
""",
        encoding="utf-8",
    )
    (repo / "backend" / "billing" / "services.py").write_text(
        """
from billing.models import LedgerEntry

def list_entries():
    return list(LedgerEntry.objects.filter(amount__gt=0))
""",
        encoding="utf-8",
    )
    (repo / "backend" / "billing" / "views.py").write_text(
        """
from billing.services import list_entries

def ledger_list_view(request):
    return list_entries()
""",
        encoding="utf-8",
    )
    (repo / "backend" / "billing" / "urls.py").write_text(
        """
from django.urls import path
from billing import views

urlpatterns = [
    path("api/ledger/", views.ledger_list_view),
]
""",
        encoding="utf-8",
    )
    # Place <template> lines above <script setup> to verify line-number preservation in .vue SFCs.
    (repo / "frontend" / "src" / "pages" / "ledger.vue").write_text(
        """<template>
  <section>
    <h1>Ledger</h1>
  </section>
</template>
<script setup lang="ts">
const MAX_CAPACITY_LIMIT = 40;
const todayIso = new Date().toISOString().slice(0, 10);
const entries = await $fetch('/api/ledger/');
</script>
""",
        encoding="utf-8",
    )

    det = detect_repository_stack(db_session, str(repo))
    assert det.recommended_profile_slug == "django-vue"

    target = TargetProject(
        id=0,
        slug="django-vue-demo",
        name="Django Vue Demo",
        repo_path=str(repo),
        stack_profile_slug="django-vue",
        backend_subdir=det.backend_subdir,
        frontend_subdir=det.frontend_subdir,
        description="Synthetic Django + Vue",
        is_active=True,
    )
    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)

    assert report.summary.truth_tables == 1
    assert report.summary.end_to_end_chains == 1
    chain = report.chains[0]
    assert "t:ledger_entries" in chain.truth_table_ids

    by_rule = {f.rule_code: f for f in report.findings}
    assert "DISP-001" in by_rule
    assert by_rule["DISP-001"].line == 7
    assert "DISP-002" in by_rule
    assert by_rule["DISP-002"].line == 8


def test_go_chi_sqlc_and_sveltekit_end_to_end_lineage_and_manip_rules(
    db_session: Session, tmp_path: Path
) -> None:
    """Verify Go chi router + sqlc query annotations + schema.sql + SvelteKit +page.svelte scan."""
    repo = tmp_path / "go_svelte_repo"
    (repo / "backend" / "db" / "queries").mkdir(parents=True)
    (repo / "backend" / "internal" / "service").mkdir(parents=True)
    (repo / "backend" / "internal" / "api").mkdir(parents=True)
    (repo / "frontend" / "src" / "lib").mkdir(parents=True)
    (repo / "frontend" / "src" / "routes" / "bookings").mkdir(parents=True)

    (repo / "backend" / "go.mod").write_text("module example.com/app\n\ngo 1.23\n", encoding="utf-8")
    (repo / "frontend" / "svelte.config.js").write_text("export default {};\n", encoding="utf-8")
    (repo / "frontend" / "package.json").write_text(
        '{"devDependencies": {"@sveltejs/kit": "2.0.0"}}',
        encoding="utf-8",
    )

    (repo / "backend" / "db" / "schema.sql").write_text(
        """
CREATE TABLE bookings (
    id BIGSERIAL PRIMARY KEY,
    guest_name TEXT NOT NULL
);
""",
        encoding="utf-8",
    )
    (repo / "backend" / "db" / "queries" / "bookings.sql").write_text(
        """
-- name: ListBookings :many
SELECT id, guest_name FROM bookings;

-- name: CreateBooking :one
INSERT INTO bookings (guest_name) VALUES ($1) RETURNING id, guest_name;
""",
        encoding="utf-8",
    )
    (repo / "backend" / "internal" / "service" / "booking_service.go").write_text(
        """package service

import "time"

const MaxShiftCapacity = 80

func FetchAndCreate(q Queries) {
    _ = time.Now()
    q.ListBookings()
    q.CreateBooking()
}
""",
        encoding="utf-8",
    )
    (repo / "backend" / "internal" / "api" / "router.go").write_text(
        """package api

import "example.com/app/internal/service"

func RegisterRoutes(r Router, q service.Queries) {
    r.Get("/api/v1/bookings", func() { service.FetchAndCreate(q) })
    r.Post("/api/v1/bookings", func() { service.FetchAndCreate(q) })
}
""",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "lib" / "api.ts").write_text(
        """
import type { paths } from './api-generated';
export async function loadBookings() {
  return fetch('/api/v1/bookings');
}
export async function saveBooking() {
  return fetch('/api/v1/bookings', { method: 'POST' });
}
""",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "routes" / "bookings" / "+page.svelte").write_text(
        """<script lang="ts">
import { loadBookings, saveBooking } from '$lib/api';
void loadBookings();
void saveBooking();
</script>
<h1>Bookings</h1>
""",
        encoding="utf-8",
    )

    det = detect_repository_stack(db_session, str(repo))
    assert det.recommended_profile_slug == "go-sqlc-sveltekit"

    target = TargetProject(
        id=0,
        slug="go-svelte-demo",
        name="Go Svelte Demo",
        repo_path=str(repo),
        stack_profile_slug="go-sqlc-sveltekit",
        backend_subdir=det.backend_subdir,
        frontend_subdir=det.frontend_subdir,
        description="Synthetic Go + sqlc + SvelteKit",
        is_active=True,
    )
    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)

    assert report.summary.truth_tables == 1
    assert report.summary.end_to_end_chains == 2
    assert all("t:bookings" in c.truth_table_ids for c in report.chains)

    rule_codes = {f.rule_code for f in report.findings}
    assert "MANIP-001" in rule_codes
    assert "MANIP-002" in rule_codes
    assert "DISP-004" not in rule_codes
