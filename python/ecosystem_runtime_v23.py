"""Actual fixed-fixture framework and ORM runtime checks across CPython minors.

Only official prebuilt wheel dependencies installed in a separately pinned,
owner-private --target directory are imported. This is NOT a sandbox for
unknown user source, nor a production web/database/queue deployment. No
network ports, GPUs, external databases, or arbitrary project code run.
"""

import argparse
import asyncio
import importlib.metadata
import json
import os
from pathlib import Path
import re
import stat
import sys


PRIMARY_PINS = {"django": "4.2.27", "fastapi": "0.120.4", "flask": "3.1.2",
                "sqlalchemy": "2.0.44", "celery": "5.5.3", "redis": "6.4.0"}
NUMERIC_PINS = {
    "3.9": ("2.0.2", "2.3.3"),
    "3.10": ("2.2.6", "2.3.3"),
    "3.11": ("2.4.6", "3.1.0"),
    "3.12": ("2.5.4", "3.1.0"),
    "3.13": ("2.5.4", "3.1.0"),
    "3.14": ("2.5.4", "3.1.0"),
    "3.15": ("2.5.4", "3.1.0"),
}
NUMPY_ABI_ERRORS = (
    ("NUMPY_DTYPE_ABI_SIZE_MISMATCH", re.compile(r"numpy\.dtype size changed", re.I)),
    ("NUMPY_NATIVE_API_VERSION_MISMATCH", re.compile(r"module compiled against API version", re.I)),
    ("NUMPY_NATIVE_SYMBOL_MISSING", re.compile(r"undefined symbol: PyArray_", re.I)),
)


_REVIEWED_WINDOWS_MANIFESTS = {'3.9': 'f76f05fe23e2f2ce92723fb6d4c1f2f890db9ef54025abd92ee4eb3385c8f71e', '3.10': 'd298be1f78846be2717a96ad4014cfa2e9875f2ffb23544c2bd6e0d1d894e6c4', '3.11': 'ed48bda2ab15334dc16db62ac0c03a56b71928b10a383cae8d6e54b127d5fb5b', '3.12': '097b4484f2183ed9977e2b65d8ec3753b8992cddd8c88869eb32542be248db0e', '3.13': '00b8fc5e57e049970ad22312e903a9a951fc603849361d858dc7347352fc0153', '3.14': '0f94b44a7d90019493d9c09b98a30f8ae5f2474f6ce25ef2908dcf6d44e069b1', '3.15': 'cfa96ca9157e5a6dc2aec4dc77e51857a91cbc331d703f23f962f2f52291ab33'}  # Exact independently reviewed local fixed-fixture manifests.


def _verified_windows_target(path):
    import importlib.util
    helper = globals().get("_RPH_ECOSYSTEM_INTEGRITY")
    if helper is None:
        location = Path(__file__).with_name("ecosystem_wheel_integrity_v030.py")
        spec = importlib.util.spec_from_file_location("_fixed_ecosystem_integrity", location)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
    minor = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
    expected = _REVIEWED_WINDOWS_MANIFESTS.get(minor)
    if expected is None:
        raise ValueError("independently_reviewed_windows_wheel_bundle_required")
    result = helper.verify_private_target(path, expected)
    actual = "{}.{}.{}".format(*sys.version_info[:3])
    if result["runtime"] != actual:
        raise ValueError("reviewed_wheel_runtime_identity_mismatch")


def prepare_pinned_target(target):
    """Refuse symlink/public targets and mismatched versions, no imports yet."""
    path = Path(target)
    if os.name == "nt":
        _verified_windows_target(path)
    else:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077
                or info.st_uid != os.getuid()):
            raise ValueError("private_pinned_wheel_target_required")
    absolute = path.resolve()
    if str(absolute) not in sys.path:
        sys.path.insert(0, str(absolute))
    versions = {}
    for package, expected in PRIMARY_PINS.items():
        try:
            version = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError as error:
            raise ValueError("pinned_wheel_missing:" + package) from error
        if version != expected:
            raise ValueError("pinned_wheel_version_mismatch:" + package)
        versions[package] = version
    return versions


def prepare_numeric_target(target):
    versions = prepare_pinned_target(target)
    minor = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
    if minor not in NUMERIC_PINS:
        raise ValueError("unsupported_python_numeric_minor")
    for package, expected in zip(("numpy", "pandas"), NUMERIC_PINS[minor]):
        try:
            actual = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError as error:
            raise ValueError("numeric_wheel_missing:" + package) from error
        if actual != expected:
            raise ValueError("numeric_wheel_pin_mismatch:" + package)
        versions[package] = actual
    return versions


def classify_numpy_native_abi_error(trace_bytes):
    """Classify bounded captured errors only, never execute an invalid binary."""
    if type(trace_bytes) is not bytes or len(trace_bytes) > 65536:
        raise ValueError("invalid_native_abi_trace")
    lines = [line.strip() for line in trace_bytes.decode("utf-8", "replace").splitlines()
             if line.strip()]
    final_line = lines[-1][:1024] if lines else ""
    return [{"rule_id": name, "status": "CAPTURED_NATIVE_ABI_ERROR_CANDIDATE_NOT_RUNTIME",
             "unknown_native_module_loaded": False}
            for name, pattern in NUMPY_ABI_ERRORS if pattern.search(final_line)]


def trusted_numpy_fixture(target):
    """Native NumPy real shape/broadcast/dtype oracles with error negatives."""
    versions = prepare_numeric_target(target)
    import numpy as np
    from numpy._core import _multiarray_umath

    arr = np.arange(6, dtype=np.int64).reshape((2, 3))
    assert arr.shape == (2, 3) and arr.dtype.kind in ("i", "u")
    broad = np.broadcast_to(np.arange(2).reshape((2, 1)), (2, 3))
    assert broad.shape == (2, 3) and int(broad[1, 2]) == 1
    fails = []
    try:
        np.arange(6).reshape((4, 2))
    except ValueError:
        fails.append("RESHAPE_COUNT_MISMATCH")
    try:
        np.broadcast_arrays(np.ones((2, 3)), np.ones((4, 1)))
    except ValueError:
        fails.append("BROADCAST_SHAPE_MISMATCH")
    try:
        np.dtype("TRUSTED_INVALID_DTYPE_V23")
    except TypeError:
        fails.append("UNKNOWN_DTYPE_REJECTED")
    assert len(fails) == 3
    module = Path(_multiarray_umath.__file__).resolve()
    module.relative_to(Path(target).resolve())
    assert module.suffix in (".so", ".pyd", ".dylib")
    example_abi_error = classify_numpy_native_abi_error(
        b"RuntimeError: module compiled against API version 0x10 but this version of numpy is 0x12")
    assert len(example_abi_error) == 1
    return {"status": "REAL_NUMPY_NATIVE_SHAPE_DTYPE_VERIFIED",
            "python": "{}.{}".format(sys.version_info.major, sys.version_info.minor),
            "installed_pin": versions["numpy"],
            "real_native_extension_imported": True,
            "shape_after_reshape": [2, 3],
            "broadcast_output_shape": [2, 3],
            "actual_negative_runtime_oracles": fails,
            "captured_native_abi_error_classifier_verified": True,
            "incompatible_abi_binary_intentionally_not_executed": True,
            "unknown_project_code_executed": False,
            "independent_external_audit": False}


def trusted_pandas_fixture(target):
    """Real Pandas nullable dtypes, labelled indexing and schema negatives."""
    versions = prepare_numeric_target(target)
    import pandas as pd
    from pandas._libs import lib as pandas_native

    data = pd.DataFrame({"amount": pd.Series([1, None, 3], dtype="Int64"),
                         "label": ["A", "B", "C"]})
    assert list(data.columns) == ["amount", "label"]
    assert str(data["amount"].dtype) == "Int64"
    assert data["amount"].isna().sum() == 1
    assert data.loc[0, "label"] == "A"
    fails = []
    try:
        data["missing-field"]
    except KeyError:
        fails.append("MISSING_SCHEMA_COLUMN_REJECTED")
    try:
        data.loc[99, "label"]
    except KeyError:
        fails.append("INVALID_LABEL_INDEX_REJECTED")
    try:
        data.astype({"amount": "TRUSTED_NONEXISTENT_DTYPE"})
    except (TypeError, ValueError):
        fails.append("INVALID_DTYPE_REJECTED")
    assert len(fails) == 3
    module = Path(pandas_native.__file__).resolve()
    module.relative_to(Path(target).resolve())
    assert module.suffix in (".so", ".pyd", ".dylib")
    return {"status": "REAL_PANDAS_NATIVE_INDEX_DTYPE_SCHEMA_VERIFIED",
            "python": "{}.{}".format(sys.version_info.major, sys.version_info.minor),
            "installed_pin": versions["pandas"],
            "real_native_extension_imported": True,
            "nullable_integer_dtype": "Int64",
            "actual_negative_runtime_oracles": fails,
            "real_index_lookup_verified": True,
            "real_dataframe_schema_verified": True,
            "unknown_project_code_executed": False,
            "external_dataset_loaded": False,
            "independent_external_audit": False}


def trusted_web_fixture(target):
    """Real Django, FastAPI and Flask route/DI/middleware behavior, no sockets."""
    versions = prepare_pinned_target(target)
    import django
    from django.conf import settings
    from django.http import HttpRequest, HttpResponse
    from django.urls import path, resolve, reverse, Resolver404
    from django.middleware.common import CommonMiddleware
    import fastapi
    from fastapi import Depends, FastAPI
    from fastapi.routing import APIRoute
    from starlette.middleware.gzip import GZipMiddleware
    from flask import Flask, g

    if not settings.configured:
        settings.configure(DEBUG=False, SECRET_KEY="trusted-offline-fixture",
                           ALLOWED_HOSTS=["testserver"], USE_I18N=False,
                           APPEND_SLASH=False)
    django.setup()

    def django_view(request, item):
        return HttpResponse("item=" + str(item))

    routes = (path("health/<int:item>/", django_view, name="rph_health"),)
    match = resolve("/health/7/", urlconf=routes)
    assert match.kwargs == {"item": 7}
    assert reverse("rph_health", kwargs={"item": 7}, urlconf=routes) == "/health/7/"
    try:
        resolve("/missing/", urlconf=routes)
    except Resolver404:
        django_not_found = True
    else:
        django_not_found = False
    request = HttpRequest()
    request.method = "GET"
    request.path = "/health/7/"
    request.META["HTTP_HOST"] = "testserver"
    request.META["SERVER_NAME"] = "testserver"
    request.META["SERVER_PORT"] = "80"
    middleware_response = CommonMiddleware(lambda req: django_view(req, 7))(request)
    assert middleware_response.status_code == 200

    api = FastAPI()

    def dependency():
        return "verified"

    @api.get("/health/{item}")
    def api_health(item: int, marker: str = Depends(dependency)):
        return {"item": item, "marker": marker}

    api.add_middleware(GZipMiddleware, minimum_size=1024)
    api_routes = [route for route in api.routes if isinstance(route, APIRoute)]
    assert len(api_routes) == 1
    real_di = bool(api_routes[0].dependant.dependencies and
                   api_routes[0].dependant.dependencies[0].call is dependency)
    real_middleware = any(item.cls is GZipMiddleware for item in api.user_middleware)
    assert real_di and real_middleware

    flask_app = Flask("rph-trusted-flask")

    @flask_app.before_request
    def before():
        g.rph_audit = "verified"

    @flask_app.after_request
    def after(response):
        response.headers["X-RPH-Middleware"] = g.rph_audit
        return response

    @flask_app.get("/health/<int:item>")
    def flask_health(item):
        return {"item": item}

    with flask_app.test_client() as client:
        success = client.get("/health/7")
        missing = client.get("/missing")
    assert success.status_code == 200 and success.json == {"item": 7}
    assert success.headers["X-RPH-Middleware"] == "verified"
    assert missing.status_code == 404

    return {"status": "REAL_DJANGO_FASTAPI_FLASK_FIXTURE_VERIFIED",
            "python": "{}.{}".format(sys.version_info.major, sys.version_info.minor),
            "primary_pins": versions,
            "django_version": django.get_version(),
            "django_resolve_and_reverse": True,
            "django_negative_404": django_not_found,
            "django_real_middleware_response": middleware_response.status_code == 200,
            "fastapi_version": fastapi.__version__,
            "fastapi_real_route_and_dependency_graph": real_di,
            "fastapi_real_middleware_registration": real_middleware,
            "flask_real_test_client_200_and_404": True,
            "flask_real_before_after_middleware": True,
            "unknown_project_code_executed": False,
            "external_network_contacted": False,
            "external_runtime_attested": False,
            "production_web_deployment_qualified": False}


def trusted_sqlalchemy_fixture(target):
    """Real SQLAlchemy 2.0 in-memory SQLite + mismatched async/sync rejects."""
    versions = prepare_pinned_target(target)
    import sqlalchemy
    from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, select, text
    from sqlalchemy.exc import MissingGreenlet, ObjectNotExecutableError, IntegrityError, OperationalError
    from sqlalchemy.util.concurrency import await_only

    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    metadata = MetaData()
    table = Table("rph", metadata,
                  Column("id", Integer, primary_key=True),
                  Column("value", String, unique=True))
    metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(table.insert().values(id=7, value="trusted"))
        result = conn.execute(select(table.c.value).where(table.c.id == 7)).scalar_one()
        assert result == "trusted"
        query = conn.execute(text("SELECT COUNT(*) FROM rph")).scalar_one()
        assert query == 1
        try:
            conn.execute("SELECT COUNT(*) FROM rph")
        except ObjectNotExecutableError:
            raw_sql_rejected = True
        else:
            raw_sql_rejected = False
        try:
            conn.execute(table.insert().values(id=8, value="trusted"))
        except IntegrityError:
            duplicate_key_rejected = True
        else:
            duplicate_key_rejected = False
        # Actually migrate the trusted SQLite schema through SQLAlchemy;
        # compare the native PRAGMA oracle before and after and retain data.
        before_schema = [row[1] for row in conn.exec_driver_sql("PRAGMA table_info(rph)")]
        assert before_schema == ["id", "value"]
        conn.exec_driver_sql("ALTER TABLE rph ADD COLUMN migration_tag TEXT NOT NULL DEFAULT 'v1'")
        after_schema = [row[1] for row in conn.exec_driver_sql("PRAGMA table_info(rph)")]
        assert after_schema == ["id", "value", "migration_tag"]
        original_data_preserved = conn.exec_driver_sql(
            "SELECT value, migration_tag FROM rph WHERE id=7").one() == ("trusted", "v1")
        try:
            conn.exec_driver_sql("ALTER TABLE rph ADD COLUMN migration_tag TEXT")
        except OperationalError:
            duplicate_migration_rejected = True
        else:
            duplicate_migration_rejected = False
    # SQLite DDL needs an explicit BEGIN before a rollback drill. Exercise
    # the *actual* transaction, not an invented simulation of migration undo.
    with engine.connect() as conn:
        conn.exec_driver_sql("BEGIN IMMEDIATE")
        conn.exec_driver_sql("ALTER TABLE rph ADD COLUMN transient_rollback_tag TEXT")
        temporary_schema = [row[1] for row in conn.exec_driver_sql("PRAGMA table_info(rph)")]
        assert "transient_rollback_tag" in temporary_schema
        conn.exec_driver_sql("ROLLBACK")
    with engine.connect() as conn:
        restored_schema = [row[1] for row in conn.exec_driver_sql("PRAGMA table_info(rph)")]
        migration_rollback_verified = "transient_rollback_tag" not in restored_schema
        assert "migration_tag" in restored_schema
        assert conn.exec_driver_sql("SELECT COUNT(*) FROM rph").scalar_one() == 1
    coroutine = asyncio.sleep(0)
    try:
        await_only(coroutine)
    except MissingGreenlet:
        async_context_rejected = True
    else:
        async_context_rejected = False
    finally:
        coroutine.close()
        engine.dispose()
    assert (raw_sql_rejected and duplicate_key_rejected and async_context_rejected
            and duplicate_migration_rejected and original_data_preserved
            and migration_rollback_verified)
    return {"status": "REAL_SQLALCHEMY_SQLITE_ASYNC_CONTEXT_VERIFIED",
            "python": "{}.{}".format(sys.version_info.major, sys.version_info.minor),
            "primary_pins": versions,
            "sqlalchemy_version": sqlalchemy.__version__,
            "sqlite_real_insert_select_count": query,
            "legacy_raw_sql_rejected": raw_sql_rejected,
            "sqlite_duplicate_constraint_rejected": duplicate_key_rejected,
            "actual_schema_migration_committed": True,
            "actual_migration_preserved_original_row": original_data_preserved,
            "duplicate_column_migration_rejected": duplicate_migration_rejected,
            "actual_sqlite_ddl_rollback_verified": migration_rollback_verified,
            "async_without_greenlet_context_rejected": async_context_rejected,
            "external_database_contacted": False,
            "unknown_project_code_executed": False,
            "production_orm_migrations_qualified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "web", "orm", "numpy", "pandas"),
                        default="capabilities")
    parser.add_argument("--target", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.mode == "capabilities":
            result = {"status": "PINNED_REAL_FRAMEWORK_FIXTURE_ADAPTER_AVAILABLE",
                      "supported_runtime_modes": ["web", "orm", "numpy", "pandas"],
                      "private_pinned_target_required": True,
                      "real_frameworks_executed": False,
                      "unknown_project_code_executed": False,
                      "external_network_contacted": False}
        elif args.target is None:
            raise ValueError("runtime_mode_requires_private_target")
        elif args.mode == "web":
            result = trusted_web_fixture(args.target)
        elif args.mode == "orm":
            result = trusted_sqlalchemy_fixture(args.target)
        elif args.mode == "numpy":
            result = trusted_numpy_fixture(args.target)
        else:
            result = trusted_pandas_fixture(args.target)
    except (AssertionError, ValueError, OSError, ImportError, RuntimeError) as problem:
        print(json.dumps({"status": "NO_PASS_UNVERIFIED_FRAMEWORK_RUNTIME",
                          "reason_code": type(problem).__name__,
                          "unknown_project_code_executed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
