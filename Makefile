# Modified by codex: 2024-05-08

.PHONY: demo demo-ui clean-results

results := results

$(results):
	mkdir -p $(results)

demo: $(results)
	docker compose --profile runner up --build

demo-ui: $(results)
	docker compose --profile ui up --build

clean-results:
	rm -rf $(results)/*
