.PHONY: demo ui clean-results results test

results := results

results:
	mkdir -p $@

demo: results
	docker compose up --build

ui: results
	python web_ui.py

test:
	pytest -q

clean-results:
	rm -rf $(results)/*
