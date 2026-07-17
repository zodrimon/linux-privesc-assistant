.PHONY: test typecheck clean

test:
	python -m unittest discover -s tests

typecheck:
	mypy src/privesc_assistant

clean:
	find . -type d -name "__pycache__" -exec rm -r {} +
	find . -type f -name "*.pyc" -delete
