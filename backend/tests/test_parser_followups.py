"""Bounded regressions for reviewed migration and Redis parser gaps (#22–24)."""

import ast
import textwrap

import pytest

from app.adapters.postgres_sqlalchemy import _collect_migration_effects
from app.adapters.redis_ephemeral import _PyRedisCalls


def _events(source: str) -> list[tuple[str, str]]:
    result = _collect_migration_effects(ast.parse(textwrap.dedent(source)))
    return [(event[1], event[2]) for event in result.table_events]


@pytest.mark.parametrize("source", [
    '''
    KEY = "create"
    STATEMENTS = {KEY: "CREATE TABLE widgets (id INT);"}
    def upgrade():
        for sql in STATEMENTS.values():
            op.execute(sql)
    ''',
    '''
    def upgrade():
        key = "create"
        statements = {key: "CREATE TABLE widgets (id INT);"}
        for sql in statements.values():
            op.execute(sql)
    ''',
    '''
    def apply(sql):
        op.execute(sql)
    def upgrade():
        key = "sql"
        apply(**{key: "CREATE TABLE widgets (id INT);"})
    ''',
    '''
    KEY = "create"
    def upgrade():
        def apply(statements={KEY: "CREATE TABLE widgets (id INT);"}):
            for sql in statements.values():
                op.execute(sql)
        apply()
    ''',
])
def test_constant_dictionary_keys_preserve_executed_sql(source: str) -> None:
    assert _events(source) == [("create", "widgets")]


def test_resolved_dictionary_key_keeps_last_value_and_not_unexecuted_sql() -> None:
    assert _events('''
    def upgrade():
        key = "same"
        statements = {key: "CREATE TABLE retired (id INT);", "same": "CREATE TABLE active (id INT);"}
        discarded = {key: "CREATE TABLE never_executed (id INT);"}
        for sql in statements.values():
            op.execute(sql)
    ''') == [("create", "active")]


def test_nested_definitions_execute_defaults_and_decorator_expressions_only() -> None:
    assert _events('''
    def prepare():
        op.create_table("decorator_effect")
    def upgrade():
        @prepare()
        def unused(value=op.create_table("positional_default"), *, option=op.create_table("keyword_default")):
            op.create_table("unused_body")
        async def unused_async(value=op.create_table("async_default")):
            op.create_table("async_unused_body")
    def downgrade():
        def unused(value=op.create_table("downgrade_default")):
            pass
    ''') == [("create", "decorator_effect"), ("create", "positional_default"),
            ("create", "keyword_default"), ("create", "async_default")]


def test_defaults_are_captured_in_order_and_popped_only_once() -> None:
    assert _events('''
    def upgrade():
        statements = ["CREATE TABLE first (id INT);", "CREATE TABLE second (id INT);"]
        def apply(a=statements.pop(0), b=statements.pop(0)):
            op.execute(a)
            op.execute(b)
        apply()
        for remaining in statements:
            op.execute(remaining)
    ''') == [("create", "first"), ("create", "second")]


def test_default_sql_is_not_executed_until_used_and_helper_side_effect_runs_once() -> None:
    assert _events('''
    def prepare():
        op.create_table("once")
    def upgrade():
        def unused(sql="CREATE TABLE unused (id INT);", side_effect=prepare()):
            op.execute(sql)
        unused("SELECT 1")
        unused("SELECT 1")
    ''') == [("create", "once")]


@pytest.mark.parametrize("setup,arguments,bounded", [
    ("", "**dict(ex=60)", True),
    ("", "**{'px': 1000}", True),
    ("", "**({'ex': None} | {'ex': 60})", True),
    ("", "**({'ex': 60} | {'ex': None})", False),
    ("", "**dict({'ex': None}, ex=60)", True),
    ("", "**{'ex': 60}, ex=None", False),  # duplicate call keywords raise, not an override
    ("", "**{'ex': 60}, **{'ex': 30}", False),
    ("", "**unknown", False),
    ("", "**{'ex': unknown}", False),
    ("", "**{'ex': 60, **unknown}", False),
    ("", "**{'ex': 0}", False),
    ("", "**{'keepttl': True}", True),
    ("", "**{'keepttl': False}", False),
    ("opts = {'ex': 60}", "**opts", True),
    ("seconds = 60\nopts = {'ex': seconds}", "**opts", True),
    ("opts = {'ex': 60}\nopts['ex'] = None", "**opts", False),
    ("opts = {'ex': 60}\nopts.update(ex=None)", "**opts", False),
    ("opts = {'ex': 60}\nalias = opts\nalias.clear()", "**opts", False),
    ("opts = {'ex': 60}\nmutate(opts)", "**opts", False),
    ("opts = {'ex': 60}\nmutate(options=opts)", "**opts", False),
])
def test_redis_keyword_mappings_require_bounded_unambiguous_options(
    setup: str, arguments: str, bounded: bool,
) -> None:
    tree = ast.parse(f"{setup}\nredis.set('state:new', payload, {arguments})")
    calls = _PyRedisCalls(tree)
    call = tree.body[-1].value
    assert calls.has_ttl(call, "set") is bounded


def test_redis_module_constants_respect_local_shadowing() -> None:
    tree = ast.parse('''
OPTS = {'ex': 60}
def bounded():
    redis.set('state:new', payload, **OPTS)
def unknown(OPTS):
    redis.set('state:new', payload, **OPTS)
def conditional(flag):
    if flag:
        opts = {'ex': 60}
    redis.set('state:new', payload, **opts)
''')
    calls = _PyRedisCalls(tree)
    writes = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
              and isinstance(n.func, ast.Attribute) and n.func.attr == "set"]
    assert [calls.has_ttl(call, "set") for call in writes] == [True, False, False]


def test_redis_module_binding_changed_by_another_function_is_unknown() -> None:
    tree = ast.parse('''
OPTS = {'ex': 60}
def change():
    global OPTS
    OPTS = {'ex': None}
def write():
    redis.set('state:new', payload, **OPTS)
''')
    call = tree.body[-1].body[0].value
    assert _PyRedisCalls(tree).has_ttl(call, "set") is False
