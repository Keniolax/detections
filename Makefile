# detections. Run `make` to list targets.
SHELL := /bin/bash
.DEFAULT_GOAL := help
.PHONY: help convert check apply prove noise test

help: ## List the targets
	@awk -F ':.*## ' '/^[a-z-]+:.*## / { printf "  make %-8s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

convert: ## Generate wazuh/local_rules.xml from sigma/
	@python3 convert/sigma_to_wazuh.py

check: ## Validate the rules without a lab (CI runs this)
	@python3 convert/sigma_to_wazuh.py --check
	@python3 -m pytest tests -q

apply: ## Load the rules into a running home-soc-lab manager (set LAB_DIR)
	@bin/apply.sh

prove: ## Run each technique on the lab and show its rule fires (set LAB_DIR)
	@python3 bin/prove.py

noise: ## Generate benign activity and check for false positives (set LAB_DIR)
	@python3 bin/noise.py
