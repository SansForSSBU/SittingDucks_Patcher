VENV = .venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

create_venv:
	@test -d $(VENV) || python3 -m venv $(VENV)
	$(PIP) install --upgrade pip

.PHONY: setup
setup: create_venv
	sudo apt install -y build-essential python3-dev
	$(PIP) install -e .[dev]

.PHONY: test
test: setup
	. $(VENV)/bin/activate && $(PYTHON) -m pytest