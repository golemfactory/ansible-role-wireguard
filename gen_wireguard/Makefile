all: flake8 pylint mypy pytest

pytest:
	pytest -vv *.py

flake8:
	flake8 *.py

pylint:
	pylint *.py

mypy:
	mypy *.py


.PHONY: all pytest flake8 pylint mypy
