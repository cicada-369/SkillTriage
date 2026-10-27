PYTHON ?= python3
PYTHONPATH_ENV = PYTHONSAFEPATH=1 PYTHONPATH=src

.PHONY: test compile rules-doc zipapp scan security clean

test:
	$(PYTHONPATH_ENV) $(PYTHON) -m unittest discover -s tests -t . -v

compile:
	# Fixtures are inert data; compiling them would create __pycache__ inside
	# the very trees the loader audits.
	$(PYTHONPATH_ENV) $(PYTHON) -m compileall -q -x '(^|/)tests/fixtures/' src tests tools

rules-doc:
	PYTHONSAFEPATH=1 $(PYTHON) tools/gen_rules_doc.py

zipapp:
	rm -rf build/zipapp
	mkdir -p build/zipapp dist
	rm -f dist/skilltriage.pyz dist/skilltriage.pyz.sha256
	cp -r src/skilltriage build/zipapp/
	cp src/__main__.py build/zipapp/
	find build/zipapp -name __pycache__ -type d -prune -exec rm -rf {} +
	# Normalise timestamps so the archive is reproducible.
	TZ=UTC find build/zipapp -exec touch -h -t 202001010000 {} +
	$(PYTHON) -m zipapp build/zipapp -o dist/skilltriage.pyz -p "/usr/bin/env python3"
	chmod +x dist/skilltriage.pyz
	sha256sum dist/skilltriage.pyz > dist/skilltriage.pyz.sha256
	@echo "built dist/skilltriage.pyz (checksum in dist/skilltriage.pyz.sha256)"

scan:
	$(PYTHONPATH_ENV) $(PYTHON) -m skilltriage scan --format markdown -o reports/system-scan.md

security:
	$(PYTHON) -m pip_audit --skip-editable
	bandit -q -r src
	$(PYTHONPATH_ENV) $(PYTHON) -m skilltriage audit examples/secure-skill --fail-on high

clean:
	rm -rf build dist
	rm -f reports/*.md reports/*.json reports/*.sarif
