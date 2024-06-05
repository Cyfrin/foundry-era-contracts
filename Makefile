-include .env

.PHONY: all test clean deploy fund help install snapshot format anvil scopefile

DEFAULT_ANVIL_KEY := 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

all: remove install build

# Clean the repo
clean  :; forge clean

remove :; rm -rf .gitmodules && rm -rf .git/modules/* && rm -rf lib && touch .gitmodules && git add . && git commit -m "modules"

install :;  forge install openzeppelin/openzeppelin-contracts@v5.0.2 --no-commit && forge install openzeppelin/openzeppelin-contracts-upgradeable@v5.0.2 --no-commit && forge install cyfrin/murky@0.0.1 --no-commit

build :; forge build