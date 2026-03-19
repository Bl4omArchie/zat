.PHONY: help clean clean-pyc clean-build lint format test test-all coverage docs release sdist

help:
	@echo "clean-build - remove build artifacts"
	@echo "clean-pyc - remove Python file artifacts"
	@echo "lint - check style with flake8"
	@echo "format - format code with black and isort"
	@echo "test - run tests quickly with the default Python"
	@echo "test-all - run tests on every Python version with tox"
	@echo "coverage - check code coverage quickly with the default Python"
	@echo "docs - generate Sphinx HTML documentation, including API docs"
	@echo "release - package and upload a release"
	@echo "sdist - package"

clean: clean-build clean-pyc

clean-build:
	find . -name 'build' -exec rm -rf {} +
	find . -name '_build' -exec rm -rf {} +
	find . -name 'dist' -exec rm -rf {} +
	find . -name '*.egg-info' -exec rm -rf {} +
	find . -name '*.tar.gz' -exec rm -rf {} +
	find . -name '.tox' -exec rm -rf {} +
	find . -name '.coverage' -exec rm -rf {} +
	find . -name '.cache' -exec rm -rf {} +
	find . -name '__pycache__' -exec rm -rf {} +

clean-pyc:
	find . -name '*.pyc' -exec rm -rf {} +
	find . -name '*.pyo' -exec rm -rf {} +
	find . -name '*~' -exec rm -rf {} +

lint:
	flake8 zat

format:
	black zat examples explorations
	isort zat examples explorations

test:
	pytest zat

test-all:
	tox

coverage:
	pytest --cov=zat --cov-report=term-missing --cov-report=html zat
	open htmlcov/index.html

docs:
	rm -f docs/zat.rst
	rm -f docs/modules.rst
	sphinx-apidoc -o docs/ zat
	$(MAKE) -C docs clean
	$(MAKE) -C docs html
	open docs/_build/html/index.html

release: clean
	python -m build
	twine upload dist/*

sdist: clean
	python -m build
	ls -l dist
