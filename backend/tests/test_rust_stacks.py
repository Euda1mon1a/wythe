"""End-to-end 3-tier tests for Rust stacks (`axum`+`sqlx`+`Leptos`, `Tauri`+`SeaORM`+`SvelteKit`, `Diesel`)."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.adapters.autodetect import detect_repository_stack
from app.cli import main as cli_main
from app.models import TargetProject
from app.services.scanner_service import run_target_scan


def test_pure_rust_axum_sqlx_and_leptos_wasm_fullstack_lineage(
    db_session: Session, tmp_path: Path
) -> None:
    """Verify 100% Rust stack: sqlx migrations/query_file! + axum Router + Leptos/gloo-net WASM UI."""
    repo = tmp_path / "rust_leptos_repo"
    (repo / "backend" / "migrations").mkdir(parents=True)
    (repo / "backend" / "queries").mkdir(parents=True)
    (repo / "backend" / "src" / "services").mkdir(parents=True)
    (repo / "backend" / "src" / "routes").mkdir(parents=True)
    (repo / "frontend" / "src" / "pages").mkdir(parents=True)

    (repo / "backend" / "Cargo.toml").write_text(
        '[package]\nname = "srv"\n[dependencies]\naxum = "0.8"\nsqlx = "0.8"\n',
        encoding="utf-8",
    )
    (repo / "frontend" / "Cargo.toml").write_text(
        '[package]\nname = "ui"\n[dependencies]\nleptos = "0.7"\ngloo-net = "0.6"\n',
        encoding="utf-8",
    )
    (repo / "backend" / "migrations" / "0001_bookings.sql").write_text(
        "CREATE TABLE bookings (id BIGSERIAL PRIMARY KEY, guest TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "queries" / "insert_booking.sql").write_text(
        "INSERT INTO bookings (guest) VALUES ($1);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "src" / "services" / "booking_service.rs").write_text(
        """use chrono::Utc;

pub const MAX_SHIFT_CAPACITY: u32 = 80;

pub async fn load_bookings() {
    let _now = Utc::now();
    let _ = sqlx::query!("SELECT id, guest FROM bookings");
}

pub async fn save_booking() {
    let _ = sqlx::query_file!("queries/insert_booking.sql", "Alice");
}
""",
        encoding="utf-8",
    )
    (repo / "backend" / "src" / "routes" / "bookings_api.rs").write_text(
        """use axum::{routing::get, Router};
use crate::services::booking_service::{load_bookings, save_booking};

pub fn router() -> Router {
    Router::new()
        .route("/api/v1/bookings", get(load_bookings).post(save_booking))
}
""",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "api.rs").write_text(
        """use shared::BookingDto;
use gloo_net::http::Request;

pub async fn fetch_bookings() {
    let _ = Request::get("/api/v1/bookings").send().await;
    let _ = Request::post("/api/v1/bookings").send().await;
}
""",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "pages" / "bookings_page.rs").write_text(
        """use crate::api::fetch_bookings;

pub fn BookingsView() {
    let _d = js_sys::Date::new_0();
    // <Route path="/bookings" view=BookingsView />
}
""",
        encoding="utf-8",
    )

    det = detect_repository_stack(db_session, str(repo))
    assert det.recommended_profile_slug == "rust-fullstack-wasm"

    target = TargetProject(
        id=0,
        slug="rust-leptos-demo",
        name="Rust Leptos Demo",
        repo_path=str(repo),
        stack_profile_slug=det.recommended_profile_slug,
        backend_subdir=det.backend_subdir,
        frontend_subdir=det.frontend_subdir,
        description="Synthetic Pure Rust Full-Stack",
        is_active=True,
    )
    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)

    assert report.summary.truth_tables == 1
    assert report.summary.end_to_end_chains == 2
    assert all("t:bookings" in c.truth_table_ids for c in report.chains)

    codes = {f.rule_code for f in report.findings}
    assert "MANIP-001" in codes
    assert "MANIP-002" in codes
    assert "DISP-002" in codes
    assert "DISP-004" not in codes


def test_tauri_seaorm_sveltekit_ipc_lineage_and_diesel_actix_cli_gate(
    isolated_db_url: str, db_session: Session, tmp_path: Path
) -> None:
    """Verify Tauri v2 #[tauri::command] + SeaORM + SvelteKit invoke() AND Diesel + actix-web CLI gate."""
    assert isolated_db_url.startswith("sqlite:")

    # Part A: Tauri (`src-tauri`) + SeaORM + SvelteKit `invoke()`
    tauri_repo = tmp_path / "tauri_svelte_repo"
    (tauri_repo / "src-tauri" / "migrations").mkdir(parents=True)
    (tauri_repo / "src-tauri" / "src" / "entity").mkdir(parents=True)
    (tauri_repo / "src-tauri" / "src" / "services").mkdir(parents=True)
    (tauri_repo / "src-tauri" / "src" / "commands").mkdir(parents=True)
    (tauri_repo / "frontend" / "src" / "routes").mkdir(parents=True)

    (tauri_repo / "src-tauri" / "Cargo.toml").write_text(
        '[package]\nname = "app"\n[dependencies]\ntauri = "2.0"\nsea-orm = "1.1"\n',
        encoding="utf-8",
    )
    (tauri_repo / "frontend" / "svelte.config.js").write_text("export default {};\n", encoding="utf-8")
    (tauri_repo / "frontend" / "package.json").write_text(
        '{"dependencies": {"@tauri-apps/api": "2.0.0", "@sveltejs/kit": "2.0.0"}}',
        encoding="utf-8",
    )
    (tauri_repo / "src-tauri" / "migrations" / "001_notes.sql").write_text(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (tauri_repo / "src-tauri" / "src" / "entity" / "notes.rs").write_text(
        """#[sea_orm(table_name = "notes")]
pub struct Model {
    pub id: i32,
    pub body: String,
}
""",
        encoding="utf-8",
    )
    (tauri_repo / "src-tauri" / "src" / "entity" / "unmigrated_drafts.rs").write_text(
        """#[sea_orm(table_name = "unmigrated_drafts")]
pub struct Model {
    pub id: i32,
}
""",
        encoding="utf-8",
    )
    (tauri_repo / "src-tauri" / "src" / "services" / "note_service.rs").write_text(
        """pub async fn query_notes() {
    let _ = notes::Entity::find();
}
""",
        encoding="utf-8",
    )
    (tauri_repo / "src-tauri" / "src" / "commands" / "note_cmds.rs").write_text(
        """use crate::services::note_service::query_notes;

#[tauri::command]
pub async fn list_notes() {
    query_notes().await;
}

#[tauri::command]
pub async fn create_note_direct() {
    let _ = notes::Entity::insert(todo!());
}
""",
        encoding="utf-8",
    )
    (tauri_repo / "frontend" / "src" / "routes" / "+page.svelte").write_text(
        """<script lang="ts">
import { invoke } from '@tauri-apps/api/core';
void invoke('list_notes');
void invoke('create_note_direct');
</script>
""",
        encoding="utf-8",
    )

    det = detect_repository_stack(db_session, str(tauri_repo))
    assert det.backend_subdir == "src-tauri"
    assert det.recommended_profile_slug == "rust-axum-sveltekit"

    target = TargetProject(
        id=0,
        slug="tauri-notes",
        name="Tauri Notes",
        repo_path=str(tauri_repo),
        stack_profile_slug=det.recommended_profile_slug,
        backend_subdir=det.backend_subdir,
        frontend_subdir=det.frontend_subdir,
        description="Synthetic Tauri + SeaORM + SvelteKit",
        is_active=True,
    )
    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    assert report.summary.truth_tables == 2
    assert report.summary.end_to_end_chains == 2
    assert any(c.http_path == "/tauri/list_notes" and "t:notes" in c.truth_table_ids for c in report.chains)
    rule_codes = {f.rule_code for f in report.findings}
    assert "TRUTH-002" in rule_codes
    assert "TRUTH-003" in rule_codes

    # Part B: Clean Diesel + actix-web + React SPA passes `truth-atlas gate --strict` (exit 0)
    diesel_repo = tmp_path / "diesel_actix_repo"
    (diesel_repo / "backend" / "migrations" / "001_shifts").mkdir(parents=True)
    (diesel_repo / "backend" / "src" / "services").mkdir(parents=True)
    (diesel_repo / "backend" / "src" / "handlers").mkdir(parents=True)
    (diesel_repo / "frontend" / "src" / "pages").mkdir(parents=True)

    (diesel_repo / "backend" / "Cargo.toml").write_text(
        '[package]\nname = "api"\n[dependencies]\nactix-web = "4"\ndiesel = "2"\n',
        encoding="utf-8",
    )
    (diesel_repo / "frontend" / "package.json").write_text('{"dependencies": {"react": "18"}}', encoding="utf-8")
    (diesel_repo / "backend" / "migrations" / "001_shifts" / "up.sql").write_text(
        "CREATE TABLE shifts (id SERIAL PRIMARY KEY, label TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (diesel_repo / "backend" / "src" / "schema.rs").write_text(
        "diesel::table! {\n    shifts (id) {\n        id -> Int4,\n        label -> Text,\n    }\n}\n",
        encoding="utf-8",
    )
    (diesel_repo / "backend" / "src" / "services" / "shift_service.rs").write_text(
        "pub fn load_shifts() {\n    let _ = shifts::table.select(());\n}\n",
        encoding="utf-8",
    )
    (diesel_repo / "backend" / "src" / "handlers" / "shift_routes.rs").write_text(
        'use crate::services::shift_service::load_shifts;\n#[get("/api/shifts")]\npub async fn get_shifts() { load_shifts(); }\n',
        encoding="utf-8",
    )
    (diesel_repo / "frontend" / "src" / "pages" / "ShiftsPage.tsx").write_text(
        "export function ShiftsPage() { void fetch('/api/shifts'); return null; }\n",
        encoding="utf-8",
    )
    assert cli_main(["gate", "--strict", str(diesel_repo)]) == 0
