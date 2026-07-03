.PHONY: help dev test build-binary install uninstall start stop restart status logs clean

APP_DIR     := app
SERVICE_DIR := services
INSTALL_DIR ?= /opt/mcp-auth-starter
SERVICE     := mcp-auth-starter

help:
	@echo "MCP Auth Starter"
	@echo ""
	@echo "  make dev             Run the server directly with the venv's python (no build)"
	@echo "  make test            Run the test suite"
	@echo "  make build-binary    Build a single-file binary with PyInstaller"
	@echo "  make install         Install the binary + systemd service (requires root)"
	@echo "  make uninstall       Remove $(INSTALL_DIR) and the service file (requires root)"
	@echo "  make start|stop|restart|status|logs   Manage the systemd service"
	@echo "  make clean           Remove build artifacts and the local venv"

$(APP_DIR)/.venv/bin/python3:
	python3 -m venv $(APP_DIR)/.venv
	$(APP_DIR)/.venv/bin/pip install --quiet -r $(APP_DIR)/requirements.txt

dev: $(APP_DIR)/.venv/bin/python3
	cd $(APP_DIR) && .venv/bin/python3 main.py

test: $(APP_DIR)/.venv/bin/python3
	cd $(APP_DIR) && .venv/bin/python3 -m pytest ../tests -v

build-binary: $(APP_DIR)/.venv/bin/python3
	@echo "Building binary (PyInstaller)..."
	$(APP_DIR)/.venv/bin/pip install --quiet pyinstaller
	cd $(APP_DIR) && .venv/bin/python3 -m PyInstaller \
		--onefile --clean --name $(SERVICE) \
		--hidden-import uvicorn.loops.auto \
		--hidden-import uvicorn.lifespan.on \
		--hidden-import uvicorn.protocols.http.auto \
		--hidden-import uvicorn.protocols.websockets.auto \
		--hidden-import mcp.server.streamable_http \
		main.py
	@echo "✓ $(APP_DIR)/dist/$(SERVICE)"

install:
	@[ "$$(id -u)" = "0" ] || { echo "❌ Requires root: sudo make install"; exit 1; }
	@[ -f "$(APP_DIR)/dist/$(SERVICE)" ] || { echo "❌ Binary not found — run: make build-binary"; exit 1; }
	mkdir -p $(INSTALL_DIR) /etc/mcp-auth-starter
	cp $(APP_DIR)/dist/$(SERVICE) $(INSTALL_DIR)/$(SERVICE)
	chmod +x $(INSTALL_DIR)/$(SERVICE)
	@[ -f /etc/mcp-auth-starter/config.json ] || cp $(SERVICE_DIR)/config.example.json /etc/mcp-auth-starter/config.json
	@[ -f /etc/mcp-auth-starter/$(SERVICE).env ] || cp $(SERVICE_DIR)/$(SERVICE).env.example /etc/mcp-auth-starter/$(SERVICE).env
	chmod 600 /etc/mcp-auth-starter/$(SERVICE).env
	id mcp >/dev/null 2>&1 || useradd --system --no-create-home mcp
	chown -R mcp:mcp $(INSTALL_DIR)
	cp $(SERVICE_DIR)/$(SERVICE).service /lib/systemd/system/
	systemctl daemon-reload
	systemctl enable $(SERVICE)
	@echo "✅ Installed. Edit /etc/mcp-auth-starter/config.json and $(SERVICE).env, then: sudo make start"

uninstall:
	@[ "$$(id -u)" = "0" ] || { echo "❌ Requires root: sudo make uninstall"; exit 1; }
	systemctl stop $(SERVICE) 2>/dev/null || true
	systemctl disable $(SERVICE) 2>/dev/null || true
	rm -f /lib/systemd/system/$(SERVICE).service
	systemctl daemon-reload
	rm -rf $(INSTALL_DIR)
	@echo "✓ Uninstalled (config in /etc/mcp-auth-starter left in place)"

start:
	@sudo systemctl start $(SERVICE) && echo "✓ started"

stop:
	@sudo systemctl stop $(SERVICE) && echo "✓ stopped"

restart:
	@sudo systemctl restart $(SERVICE) && echo "✓ restarted"

status:
	@systemctl status $(SERVICE) --no-pager

logs:
	@journalctl -u $(SERVICE) -f

clean:
	rm -rf $(APP_DIR)/.venv $(APP_DIR)/dist $(APP_DIR)/build $(APP_DIR)/*.spec $(APP_DIR)/__pycache__ tests/__pycache__ .pytest_cache
