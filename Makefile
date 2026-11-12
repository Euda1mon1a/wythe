.PHONY: dev dev-api dev-ui scan gate test lint types build-ui package

dev: build-ui
	cd backend && .venv/bin/wythe serve .. --host 127.0.0.1 --port 8780

dev-api:
	cd backend && .venv/bin/wythe serve --host 127.0.0.1 --port 8780

dev-ui:
	cd frontend && npm run dev

scan:
	cd backend && .venv/bin/wythe scan wythe

gate:
	cd backend && .venv/bin/wythe gate --strict wythe

test:
	cd backend && .venv/bin/pytest -v

lint:
	cd backend && .venv/bin/ruff check app tests

types:
	cd backend && .venv/bin/wythe export-openapi --out ../frontend/openapi.json
	cd frontend && npm run generate:types && npm run type-check

build-ui:
	cd frontend && npm run build
	rm -rf backend/app/ui_dist && cp -R frontend/out backend/app/ui_dist

package: build-ui
	uv build
