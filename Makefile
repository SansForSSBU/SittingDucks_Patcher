VENV = .venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

$(VENV)/bin/activate:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip

.PHONY: setup
setup: $(VENV)/bin/activate
	sudo apt install -y build-essential python3-dev
	$(PIP) install -e .[dev]

.PHONY: test
test: $(VENV)/bin/activate
	$(PYTHON) -m pytest